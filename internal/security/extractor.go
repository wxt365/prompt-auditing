package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxJSONDepth = 128

var unsupportedKeys = map[string]bool{
	"file": true, "file_data": true, "file_id": true, "file_url": true,
	"image": true, "image_url": true, "input_audio": true, "audio": true,
}

func Extract(body []byte) (Payload, error) {
	return extractPayload(body, validateRegisteredStructure)
}

func extractPayload(body []byte, validate func(map[string]any) error) (Payload, error) {
	if !utf8.Valid(body) {
		return Payload{}, errors.New("请求体包含非法 UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	texts := make([]Text, 0)
	root, err := decodeValue(decoder, "", "", 0, &texts)
	if err != nil {
		return Payload{}, fmt.Errorf("JSON 无法解析或不受支持: %w", err)
	}
	if _, ok := root.(map[string]any); !ok {
		return Payload{}, errors.New("请求体根节点必须是 JSON 对象")
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return Payload{}, fmt.Errorf("请求体包含额外 JSON 值: %v", token)
		}
		return Payload{}, fmt.Errorf("JSON 尾部无效: %w", err)
	}
	if err := validate(root.(map[string]any)); err != nil {
		return Payload{}, fmt.Errorf("请求体结构无效: %w", err)
	}
	for index := range texts {
		if texts[index].Maskable && !knownTextContainer(root, texts[index].Path) {
			texts[index].Maskable = false
		}
	}
	return Payload{Root: root, Texts: texts}, nil
}

func decodeValue(decoder *json.Decoder, path, key string, depth int, texts *[]Text) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("JSON 嵌套超过 %d 层", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		if value, ok := token.(string); ok {
			*texts = append(*texts, Text{Path: path, Value: value, Maskable: isMaskableText(path, key)})
		}
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			childKey, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON 对象成员名不是字符串")
			}
			if _, exists := seen[childKey]; exists {
				return nil, fmt.Errorf("JSON 对象包含重复键: %s", childKey)
			}
			seen[childKey] = struct{}{}
			if unsupportedKeys[childKey] && !isJSONSchemaPath(path) && !(childKey == "image_url" && isImageContentPath(path)) {
				return nil, fmt.Errorf("不支持的附件字段: %s", childKey)
			}
			childPath := path + "/" + escapePointer(childKey)
			// 扩展字段名也可能携带业务内容；键名只检查，不做替换。
			*texts = append(*texts, Text{Path: childPath, Value: childKey})
			child, err := decodeValue(decoder, childPath, childKey, depth+1, texts)
			if err != nil {
				return nil, err
			}
			object[childKey] = child
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		if rawType, ok := object["type"].(string); ok && unsupportedType(rawType) && !(rawType == "input_image" && isImageContentPath(path)) {
			return nil, fmt.Errorf("不支持的附件或二进制内容类型: %s", rawType)
		}
		if image, exists := object["image_url"]; exists && isImageContentPath(path) {
			if object["type"] != "input_image" {
				return nil, fmt.Errorf("%s/image_url 必须属于 input_image 内容", path)
			}
			if err := validateImageURL(image, path+"/image_url"); err != nil {
				return nil, err
			}
			// 仅在对象类型和图片格式确认后豁免图片数据，防止扩展对象借此跳过检查。
			if strings.HasPrefix(image.(string), "data:") {
				for index := len(*texts) - 1; index >= 0; index-- {
					if (*texts)[index].Path == path+"/image_url" && (*texts)[index].Value == image {
						*texts = append((*texts)[:index], (*texts)[index+1:]...)
						break
					}
				}
			}
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for index := 0; decoder.More(); index++ {
			child, err := decodeValue(decoder, fmt.Sprintf("%s/%d", path, index), key, depth+1, texts)
			if err != nil {
				return nil, err
			}
			array = append(array, child)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return array, nil
	default:
		return nil, fmt.Errorf("意外的 JSON 分隔符: %s", delimiter)
	}
}

func isImageContentPath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 4 || parts[0] != "input" || (parts[2] != "content" && parts[2] != "output") {
		return false
	}
	_, firstErr := strconv.Atoi(parts[1])
	_, secondErr := strconv.Atoi(parts[3])
	return firstErr == nil && secondErr == nil
}

func isJSONSchemaPath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "response_format" && parts[1] == "json_schema" && parts[2] == "schema" {
		return true
	}
	if len(parts) >= 3 && parts[0] == "functions" && parts[2] == "parameters" {
		_, err := strconv.Atoi(parts[1])
		return err == nil
	}
	if len(parts) >= 4 && parts[0] == "tools" && parts[2] == "function" && parts[3] == "parameters" {
		_, err := strconv.Atoi(parts[1])
		return err == nil
	}
	if len(parts) >= 3 && parts[0] == "text" && parts[1] == "format" && parts[2] == "schema" {
		return true
	}
	for index, part := range parts {
		if part == "parameters" && isResponsesToolPath("/"+strings.Join(parts[:index], "/")) {
			return true
		}
	}
	return false
}

// 工具定义可位于顶层或 additional_tools 历史项中，并可按 namespace 嵌套。
func isResponsesToolPath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 2 && parts[0] == "input" {
		if _, err := strconv.Atoi(parts[1]); err != nil {
			return false
		}
		parts = parts[2:]
	}
	if len(parts) == 0 || len(parts)%2 != 0 {
		return false
	}
	for index := 0; index < len(parts); index += 2 {
		if parts[index] != "tools" {
			return false
		}
		if _, err := strconv.Atoi(parts[index+1]); err != nil {
			return false
		}
	}
	return true
}

func isMaskableText(path, key string) bool {
	if isJSONSchemaPath(path) {
		return key == "description" || key == "title"
	}
	if strings.HasPrefix(path, "/messages/") {
		switch key {
		case "content", "text", "arguments", "refusal":
			return true
		}
	}
	if parts := strings.Split(strings.TrimPrefix(path, "/"), "/"); len(parts) == 3 && parts[0] == "functions" && key == "description" {
		return true
	}
	if path == "/response_format/json_schema/description" {
		return true
	}
	if path == "/instructions" || path == "/input" {
		return true
	}
	if strings.HasPrefix(path, "/input/") {
		switch key {
		case "text", "content", "output", "arguments", "input":
			return true
		}
	}
	if key == "description" && isResponsesToolPath(strings.TrimSuffix(path, "/description")) {
		return true
	}
	if path == "/text/format/description" {
		return true
	}
	if strings.HasPrefix(path, "/prompt/variables/") {
		return true
	}
	return false
}

func unsupportedType(value string) bool {
	lower := strings.ToLower(value)
	if lower == "computer_call_output" {
		return true
	}
	// 按类型片段识别附件，避免把 profile 等普通类型误判为 file。
	for _, part := range strings.FieldsFunc(lower, func(r rune) bool { return r == '_' || r == '-' || r == '.' || r == '/' }) {
		if part == "image" || part == "audio" || part == "file" {
			return true
		}
	}
	return false
}

// 扩展对象里的同名 text/content 不能继承正文的可替换权限。
func knownTextContainer(root any, path string) bool {
	if isJSONSchemaPath(path) {
		return true
	}
	if key := path[strings.LastIndex(path, "/")+1:]; key == "description" && isResponsesToolPath(strings.TrimSuffix(path, "/description")) {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 3 || (parts[0] != "input" && parts[0] != "messages") {
		return true
	}
	parentPath := path[:strings.LastIndex(path, "/")]
	parent, err := resolvePointer(root, parentPath, false, "")
	if err != nil {
		return false
	}
	object, ok := parent.(map[string]any)
	if !ok {
		return false
	}
	typeName, _ := object["type"].(string)
	key := parts[len(parts)-1]
	if parts[0] == "input" {
		if len(parts) == 3 {
			switch key {
			case "content":
				return typeName == "message" || typeName == ""
			case "output":
				return typeName == "function_call_output" || typeName == "custom_tool_call_output"
			case "arguments":
				return typeName == "function_call"
			case "input":
				return typeName == "custom_tool_call"
			}
		}
		if len(parts) == 5 && key == "text" && (parts[2] == "content" || parts[2] == "output" || parts[2] == "summary") {
			item, err := resolvePointer(root, "/input/"+parts[1], false, "")
			if err != nil {
				return false
			}
			itemType, _ := item.(map[string]any)["type"].(string)
			switch itemType {
			case "", "message", "function_call_output", "custom_tool_call_output", "reasoning":
				return typeName == "input_text" || typeName == "output_text" || typeName == "reasoning_text" || typeName == "summary_text" || typeName == "text"
			}
		}
		return false
	}
	if len(parts) == 3 {
		return key == "content" || key == "refusal"
	}
	if len(parts) == 5 && parts[2] == "content" && key == "text" {
		return typeName == "text"
	}
	if key == "arguments" && len(parts) == 4 && parts[2] == "function_call" {
		return true
	}
	if key == "arguments" && len(parts) == 6 && parts[2] == "tool_calls" && parts[4] == "function" {
		call, err := resolvePointer(root, "/messages/"+parts[1]+"/tool_calls/"+parts[3], false, "")
		return err == nil && call.(map[string]any)["type"] == "function"
	}
	return false
}

func escapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func Marshal(payload Payload) ([]byte, error) {
	return json.Marshal(payload.Root)
}
