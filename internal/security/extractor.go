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

var supportedRootFields = map[string]bool{
	"background": true, "client_metadata": true, "conversation": true, "include": true, "input": true,
	"instructions": true, "max_output_tokens": true, "max_tool_calls": true,
	"metadata": true, "model": true, "parallel_tool_calls": true, "prompt": true,
	"prompt_cache_key": true, "prompt_cache_retention": true, "reasoning": true,
	"safety_identifier": true, "service_tier": true, "store": true, "stream": true,
	"stream_options": true, "temperature": true, "text": true, "tool_choice": true,
	"tools": true, "top_logprobs": true, "top_p": true, "truncation": true, "user": true,
}

var unsupportedKeys = map[string]bool{
	"file": true, "file_data": true, "file_id": true, "file_url": true,
	"image": true, "image_url": true, "input_audio": true, "audio": true,
}

func Extract(body []byte) (Payload, error) {
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
	if err := validateRegisteredStructure(root.(map[string]any)); err != nil {
		return Payload{}, fmt.Errorf("请求体结构未登记: %w", err)
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
			if unsupportedKeys[childKey] && !isJSONSchemaPath(path) {
				return nil, fmt.Errorf("不支持的附件字段: %s", childKey)
			}
			childPath := path + "/" + escapePointer(childKey)
			if isDynamicObjectKey(path) {
				*texts = append(*texts, Text{Path: childPath, Value: childKey})
			}
			child, err := decodeValue(decoder, childPath, childKey, depth+1, texts)
			if err != nil {
				return nil, err
			}
			if depth == 0 && !supportedRootFields[childKey] && containsTextOrStructure(child) {
				return nil, fmt.Errorf("未登记字段包含可检查内容: %s", childKey)
			}
			object[childKey] = child
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		if rawType, ok := object["type"].(string); ok && unsupportedType(rawType) {
			return nil, fmt.Errorf("不支持的附件或二进制内容类型: %s", rawType)
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

func isJSONSchemaPath(path string) bool {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "text" && parts[1] == "format" && parts[2] == "schema" {
		return true
	}
	if len(parts) < 3 || parts[0] != "tools" || parts[2] != "parameters" {
		return false
	}
	_, err := strconv.Atoi(parts[1])
	return err == nil
}

func isDynamicObjectKey(path string) bool {
	if path == "/metadata" || path == "/client_metadata" || path == "/prompt/variables" {
		return true
	}
	if !isJSONSchemaPath(path) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 {
		return false
	}
	switch parts[len(parts)-1] {
	case "properties", "patternProperties", "$defs", "definitions", "dependentSchemas", "dependentRequired", "dependencies":
		return true
	default:
		return false
	}
}

func isMaskableText(path, key string) bool {
	if path == "/instructions" || path == "/input" {
		return true
	}
	if strings.HasPrefix(path, "/input/") {
		switch key {
		case "text", "content", "output", "arguments":
			return true
		}
	}
	if strings.HasPrefix(path, "/tools/") && key == "description" {
		return true
	}
	if path == "/text/format/description" {
		return true
	}
	if strings.HasPrefix(path, "/prompt/variables/") {
		return true
	}
	return isJSONSchemaPath(path) && (key == "description" || key == "title")
}

func unsupportedType(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "image") || strings.Contains(lower, "audio") ||
		strings.Contains(lower, "file") || lower == "computer_call_output"
}

func containsTextOrStructure(value any) bool {
	switch value.(type) {
	case string, map[string]any, []any:
		return true
	default:
		return false
	}
}

func escapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func Marshal(payload Payload) ([]byte, error) {
	return json.Marshal(payload.Root)
}
