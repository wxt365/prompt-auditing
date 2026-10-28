package security

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// 校验已知字段类型；扩展 JSON 由提取器递归检查，不以字段白名单拒绝。
func validateRegisteredStructure(root map[string]any) error {
	if _, exists := root["messages"]; exists {
		return fmt.Errorf("Responses 不支持 Chat Completions 的 /messages 字段")
	}
	for key, value := range root {
		var err error
		switch key {
		case "background", "parallel_tool_calls", "store", "stream":
			err = requireType(value, key, isBool)
		case "max_output_tokens", "max_tool_calls", "temperature", "top_logprobs", "top_p":
			err = requireType(value, key, isNumber)
		case "instructions", "model", "prompt_cache_key", "prompt_cache_retention", "safety_identifier", "service_tier", "truncation", "user":
			err = requireType(value, key, isString)
		case "include":
			err = validateStringArray(value, "/include")
		case "input":
			err = validateInput(value)
		case "tools":
			err = validateTools(value)
		case "reasoning":
			err = validateObject(value, "/reasoning", map[string]valueValidator{
				"effort": scalar(isString), "summary": scalar(isString), "context": scalar(isString),
			})
		case "text":
			err = validateText(value)
		case "stream_options":
			err = validateObject(value, "/stream_options", map[string]valueValidator{
				"include_obfuscation": scalar(isBool),
			})
		case "client_metadata", "metadata":
			err = validateObject(value, "/"+key, nil)
		case "conversation":
			err = validateStringOrObject(value, "/conversation", map[string]valueValidator{"id": scalar(isString)})
		case "prompt":
			err = validateObject(value, "/prompt", map[string]valueValidator{
				"id": scalar(isString), "version": scalar(isString), "variables": validateScalarMap,
			})
		case "tool_choice":
			err = validateToolChoice(value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type valueValidator func(any, string) error

func scalar(predicate func(any) bool) valueValidator {
	return func(value any, path string) error {
		return requireType(value, path, predicate)
	}
}

func validateInput(value any) error {
	if value == nil || isString(value) {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("/input 必须是字符串或数组")
	}
	for index, item := range items {
		path := fmt.Sprintf("/input/%d", index)
		object, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s 必须是对象", path)
		}
		typeName, ok := object["type"].(string)
		if _, exists := object["type"]; !exists {
			// 消息简写允许省略 type，仍校验角色和正文，并保持转发结构不变。
			switch object["role"] {
			case "system", "developer", "user", "assistant":
			default:
				return fmt.Errorf("%s/role 必须是有效的消息角色", path)
			}
			if content, exists := object["content"]; !exists || content == nil {
				return fmt.Errorf("%s/content 必须是字符串或内容数组", path)
			}
			typeName, ok = "message", true
		}
		if !ok || typeName == "" {
			return fmt.Errorf("%s/type 必须是字符串", path)
		}
		var fields map[string]valueValidator
		switch typeName {
		case "additional_tools":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "role": scalar(isString),
				"tools": validateToolsAt,
			}
		case "message":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"role": scalar(isString), "content": validateContent, "phase": scalar(isString),
			}
		case "function_call_output":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"call_id": scalar(isString), "output": validateContent,
				"name": scalar(isString), "namespace": scalar(isString),
			}
		case "function_call":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"call_id": scalar(isString), "name": scalar(isString), "arguments": scalar(isString),
				"namespace": scalar(isString), "encrypted_function_args": validateStringArray,
			}
		case "custom_tool_call":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"call_id": scalar(isString), "name": scalar(isString), "input": scalar(isString),
				"namespace": scalar(isString),
			}
		case "custom_tool_call_output":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"call_id": scalar(isString), "output": validateContent,
				"name": scalar(isString),
			}
		case "reasoning":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"encrypted_content": scalar(isString), "summary": validateSummary,
				"content": validateReasoningContent,
			}
		default:
			// 新增的纯 JSON 历史类型仍须经过递归审计，暂不推断可替换字段。
			fields = map[string]valueValidator{"type": scalar(isString)}
		}
		fields["internal_chat_message_metadata_passthrough"] = func(value any, path string) error {
			return validateObject(value, path, map[string]valueValidator{"turn_id": scalar(isString)})
		}
		if err := validateKnownFields(object, path, fields); err != nil {
			return err
		}
	}
	return nil
}

func validateContent(value any, path string) error {
	if value == nil || isString(value) {
		return nil
	}
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s 必须是字符串或文本数组", path)
	}
	for index, item := range items {
		itemPath := fmt.Sprintf("%s/%d", path, index)
		object, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s 必须是对象", itemPath)
		}
		typeName, ok := object["type"].(string)
		if !ok || typeName == "" {
			return fmt.Errorf("%s/type 必须是非空字符串", itemPath)
		}
		fields := map[string]valueValidator{"type": scalar(isString)}
		if typeName == "input_text" || typeName == "output_text" {
			fields["text"] = scalar(isString)
		}
		if typeName == "input_image" {
			if !isImageContentPath(itemPath) {
				return fmt.Errorf("%s 不支持图片内容", itemPath)
			}
			if err := validateImageURL(object["image_url"], itemPath+"/image_url"); err != nil {
				return err
			}
			fields = map[string]valueValidator{"type": scalar(isString), "image_url": validateImageURL, "detail": func(value any, path string) error {
				switch value {
				case "auto", "low", "high", "original":
					return nil
				default:
					return fmt.Errorf("%s 图片精度无效", path)
				}
			}}
		}
		if typeName == "output_text" {
			fields["annotations"] = validateAnnotations
			fields["logprobs"] = validateLogprobs
		}
		if err := validateKnownFields(object, itemPath, fields); err != nil {
			return err
		}
	}
	return nil
}

func validateLogprobs(value any, path string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s 必须是数组", path)
	}
	for index, item := range items {
		itemPath := fmt.Sprintf("%s/%d", path, index)
		if err := validateLogprobToken(item, itemPath, true); err != nil {
			return err
		}
	}
	return nil
}

func validateLogprobToken(value any, path string, alternatives bool) error {
	object, ok := value.(map[string]any)
	if !ok || !isString(object["token"]) || !isNumber(object["logprob"]) {
		return fmt.Errorf("%s 必须包含字符串 token 和数值 logprob", path)
	}
	fields := map[string]valueValidator{"token": scalar(isString), "logprob": scalar(isNumber)}
	if alternatives {
		fields["top_logprobs"] = func(value any, path string) error {
			items, ok := value.([]any)
			if !ok {
				return fmt.Errorf("%s 必须是数组", path)
			}
			for index, item := range items {
				if err := validateLogprobToken(item, fmt.Sprintf("%s/%d", path, index), false); err != nil {
					return err
				}
			}
			return nil
		}
	}
	// token 文本由通用提取器纳入审计；保持不可替换，避免破坏分词与概率对应关系。
	return validateKnownFields(object, path, fields)
}

func validateImageURL(value any, path string) error {
	text, ok := value.(string)
	if !ok || text == "" {
		return fmt.Errorf("%s 必须是图片 URL", path)
	}
	if strings.HasPrefix(text, "data:") {
		header, body, found := strings.Cut(text, ",")
		if !found || body == "" {
			return fmt.Errorf("%s 图片数据格式无效", path)
		}
		switch header {
		case "data:image/png;base64", "data:image/jpeg;base64", "data:image/webp;base64", "data:image/gif;base64":
		default:
			return fmt.Errorf("%s 图片格式未支持", path)
		}
		if _, err := base64.StdEncoding.Strict().DecodeString(body); err != nil {
			return fmt.Errorf("%s 图片 Base64 无效", path)
		}
		return nil
	}
	parsed, err := url.Parse(text)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("%s 必须是 HTTP 图片地址或内嵌图片", path)
	}
	return nil
}

func validateSummary(value any, path string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s 必须是数组", path)
	}
	for index, item := range items {
		itemPath := fmt.Sprintf("%s/%d", path, index)
		object, ok := item.(map[string]any)
		if !ok || !isString(object["type"]) || object["type"] == "" {
			return fmt.Errorf("%s/type 必须是非空字符串", itemPath)
		}
		fields := map[string]valueValidator{"type": scalar(isString)}
		if object["type"] == "summary_text" {
			fields["text"] = scalar(isString)
		}
		if err := validateKnownFields(object, itemPath, fields); err != nil {
			return err
		}
	}
	return nil
}

func validateTools(value any) error {
	return validateToolsAt(value, "/tools")
}

func validateToolsAt(value any, path string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s 必须是数组", path)
	}
	for index, item := range items {
		path := fmt.Sprintf("%s/%d", path, index)
		object, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s 必须是对象", path)
		}
		var fields map[string]valueValidator
		switch object["type"] {
		case "namespace":
			fields = map[string]valueValidator{
				"type": scalar(isString), "name": scalar(isString), "description": scalar(isString),
				"tools": validateToolsAt,
			}
		case "function":
			fields = map[string]valueValidator{
				"type": scalar(isString), "name": scalar(isString), "description": scalar(isString),
				"parameters": validateJSONSchema, "strict": scalar(isBool),
			}
		case "custom":
			fields = map[string]valueValidator{
				"type": scalar(isString), "name": scalar(isString), "description": scalar(isString),
				"format": validateCustomToolFormat,
			}
		case "tool_search":
			fields = map[string]valueValidator{
				"type": scalar(isString), "description": scalar(isString),
				"parameters": validateJSONSchema, "execution": scalar(isString),
			}
		case "web_search":
			fields = map[string]valueValidator{
				"type": scalar(isString), "external_web_access": scalar(isBool),
			}
		default:
			typeName, ok := object["type"].(string)
			if !ok || typeName == "" {
				return fmt.Errorf("%s/type 必须是非空字符串", path)
			}
			fields = map[string]valueValidator{"type": scalar(isString)}
		}
		if err := validateKnownFields(object, path, fields); err != nil {
			return err
		}
	}
	return nil
}

func validateReasoningContent(value any, path string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s 必须是数组", path)
	}
	for index, item := range items {
		itemPath := fmt.Sprintf("%s/%d", path, index)
		object, ok := item.(map[string]any)
		if !ok || !isString(object["type"]) || object["type"] == "" {
			return fmt.Errorf("%s/type 必须是非空字符串", itemPath)
		}
		fields := map[string]valueValidator{"type": scalar(isString)}
		if object["type"] == "reasoning_text" || object["type"] == "text" {
			fields["text"] = scalar(isString)
		}
		if err := validateKnownFields(object, itemPath, fields); err != nil {
			return err
		}
	}
	return nil
}

func validateCustomToolFormat(value any, path string) error {
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s 必须是对象", path)
	}
	typeName, ok := object["type"].(string)
	if !ok {
		return fmt.Errorf("%s/type 必须是字符串", path)
	}
	fields := map[string]valueValidator{"type": scalar(isString)}
	switch typeName {
	case "text":
	case "grammar":
		fields["syntax"] = scalar(isString)
		fields["definition"] = scalar(isString)
	default:
		// 扩展格式中的字符串已经由提取器纳入审计。
	}
	return validateKnownFields(object, path, fields)
}

func validateText(value any) error {
	return validateObject(value, "/text", map[string]valueValidator{
		"verbosity": scalar(isString),
		"format": func(value any, path string) error {
			object, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s 必须是对象", path)
			}
			typeName, ok := object["type"].(string)
			if !ok {
				return fmt.Errorf("%s/type 必须是字符串", path)
			}
			fields := map[string]valueValidator{"type": scalar(isString)}
			if typeName == "json_schema" {
				fields["name"] = scalar(isString)
				fields["description"] = scalar(isString)
				fields["schema"] = validateJSONSchema
				fields["strict"] = scalar(isBool)
			}
			return validateKnownFields(object, path, fields)
		},
	})
}

func validateToolChoice(value any) error {
	if isString(value) {
		return nil
	}
	object, ok := value.(map[string]any)
	if !ok || !isString(object["type"]) {
		return fmt.Errorf("/tool_choice 必须是字符串或带 type 的对象")
	}
	return validateKnownFields(object, "/tool_choice", map[string]valueValidator{
		"type": scalar(isString), "name": scalar(isString),
	})
}

func validateJSONSchema(value any, path string) error {
	if _, ok := value.(map[string]any); !ok {
		return fmt.Errorf("%s 必须是 JSON Schema 对象", path)
	}
	return nil
}

func validateScalarMap(value any, path string) error {
	if value == nil {
		return nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s 必须是对象", path)
	}
	for key, item := range object {
		if item != nil && !isString(item) && !isBool(item) && !isNumber(item) {
			return fmt.Errorf("%s/%s 必须是标量", path, key)
		}
	}
	return nil
}

func validateStringArray(value any, path string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s 必须是字符串数组", path)
	}
	for index, item := range items {
		if !isString(item) {
			return fmt.Errorf("%s/%d 必须是字符串", path, index)
		}
	}
	return nil
}

func validateAnnotations(value any, path string) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("%s 必须是数组", path)
	}
	for index, item := range items {
		if _, ok := item.(map[string]any); !ok {
			return fmt.Errorf("%s/%d 必须是对象", path, index)
		}
	}
	return nil
}

func validateStringOrObject(value any, path string, fields map[string]valueValidator) error {
	if isString(value) {
		return nil
	}
	return validateObject(value, path, fields)
}

func validateObject(value any, path string, fields map[string]valueValidator) error {
	if value == nil {
		return nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s 必须是对象", path)
	}
	return validateKnownFields(object, path, fields)
}

func validateKnownFields(object map[string]any, path string, fields map[string]valueValidator) error {
	for key, value := range object {
		validator, ok := fields[key]
		if !ok {
			// 所有扩展键和值已在解析时检查；保留原字段交由上游解释。
			continue
		}
		if value != nil {
			if err := validator(value, path+"/"+key); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireType(value any, path string, predicate func(any) bool) error {
	if value == nil || predicate(value) {
		return nil
	}
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	return fmt.Errorf("%s 类型无效", path)
}

func isString(value any) bool {
	_, ok := value.(string)
	return ok
}

func isBool(value any) bool {
	_, ok := value.(bool)
	return ok
}

func isNumber(value any) bool {
	_, ok := value.(json.Number)
	return ok
}
