package security

import "fmt"

// 两种接口独立校验已知字段，扩展 JSON 共用递归检测与原样转发。
func ExtractChatCompletions(body []byte) (Payload, error) {
	return extractPayload(body, validateChatStructure)
}

func validateChatStructure(root map[string]any) error {
	if _, exists := root["input"]; exists {
		return fmt.Errorf("Chat Completions 不支持 Responses 的 /input 字段")
	}
	messages, ok := root["messages"].([]any)
	if !ok || len(messages) == 0 {
		return fmt.Errorf("/messages 必须是非空数组")
	}
	for index, value := range messages {
		path := fmt.Sprintf("/messages/%d", index)
		message, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s 必须是对象", path)
		}
		if _, ok := message["role"].(string); !ok {
			return fmt.Errorf("%s/role 必须是字符串", path)
		}
		if err := validateKnownFields(message, path, map[string]valueValidator{
			"role": scalar(isString), "content": validateChatContent,
			"name": scalar(isString), "tool_call_id": scalar(isString),
			"refusal": scalar(isString), "tool_calls": validateChatToolCalls,
			"function_call": validateChatFunctionCall,
		}); err != nil {
			return err
		}
	}
	for key, value := range root {
		var err error
		switch key {
		case "model", "user", "service_tier", "reasoning_effort", "verbosity", "safety_identifier", "prompt_cache_key", "prompt_cache_retention":
			err = requireType(value, key, isString)
		case "stream", "store", "parallel_tool_calls", "logprobs":
			err = requireType(value, key, isBool)
		case "temperature", "top_p", "n", "max_tokens", "max_completion_tokens", "presence_penalty", "frequency_penalty", "top_logprobs", "seed":
			err = requireType(value, key, isNumber)
		case "metadata":
			err = validateObject(value, "/metadata", nil)
		case "logit_bias":
			err = validateScalarMap(value, "/logit_bias")
		case "stop":
			if value != nil && !isString(value) {
				err = validateStringArray(value, "/stop")
			}
		case "stream_options":
			err = validateObject(value, "/stream_options", map[string]valueValidator{
				"include_usage": scalar(isBool), "include_obfuscation": scalar(isBool),
			})
		case "tools":
			err = validateChatTools(value)
		case "functions":
			err = validateChatFunctions(value)
		case "function_call":
			err = validateStringOrObject(value, "/function_call", map[string]valueValidator{"name": scalar(isString)})
		case "tool_choice":
			if !isString(value) {
				err = validateObject(value, "/tool_choice", map[string]valueValidator{
					"type": scalar(isString), "function": func(v any, p string) error {
						return validateObject(v, p, map[string]valueValidator{"name": scalar(isString)})
					},
				})
			}
		case "response_format":
			err = validateChatResponseFormat(value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func validateChatContent(value any, path string) error {
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
		if !ok || !isString(object["type"]) || object["type"] == "" {
			return fmt.Errorf("%s/type 必须是非空字符串", itemPath)
		}
		fields := map[string]valueValidator{"type": scalar(isString)}
		if object["type"] == "text" {
			fields["text"] = scalar(isString)
		}
		if err := validateKnownFields(object, itemPath, fields); err != nil {
			return err
		}
	}
	return nil
}

func validateChatFunctionCall(value any, path string) error {
	return validateObject(value, path, map[string]valueValidator{
		"name": scalar(isString), "arguments": scalar(isString),
	})
}

func validateChatToolCalls(value any, path string) error {
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
		if err := validateKnownFields(object, itemPath, map[string]valueValidator{
			"id": scalar(isString), "type": scalar(isString), "function": validateChatFunctionCall,
		}); err != nil {
			return err
		}
	}
	return nil
}

func validateChatFunction(value any, path string) error {
	return validateObject(value, path, map[string]valueValidator{
		"name": scalar(isString), "description": scalar(isString),
		"parameters": validateJSONSchema, "strict": scalar(isBool),
	})
}

func validateChatFunctions(value any) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("/functions 必须是数组")
	}
	for index, item := range items {
		if err := validateChatFunction(item, fmt.Sprintf("/functions/%d", index)); err != nil {
			return err
		}
	}
	return nil
}

func validateChatTools(value any) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("/tools 必须是数组")
	}
	for index, item := range items {
		path := fmt.Sprintf("/tools/%d", index)
		object, ok := item.(map[string]any)
		if !ok || !isString(object["type"]) || object["type"] == "" {
			return fmt.Errorf("%s/type 必须是非空字符串", path)
		}
		if err := validateKnownFields(object, path, map[string]valueValidator{
			"type": scalar(isString), "function": validateChatFunction,
		}); err != nil {
			return err
		}
	}
	return nil
}

func validateChatResponseFormat(value any) error {
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("/response_format 必须是对象")
	}
	fields := map[string]valueValidator{"type": scalar(isString)}
	switch object["type"] {
	case "text", "json_object":
	case "json_schema":
		fields["json_schema"] = func(v any, p string) error {
			return validateObject(v, p, map[string]valueValidator{
				"name": scalar(isString), "description": scalar(isString),
				"schema": validateJSONSchema, "strict": scalar(isBool),
			})
		}
	default:
		if !isString(object["type"]) || object["type"] == "" {
			return fmt.Errorf("/response_format/type 必须是非空字符串")
		}
	}
	return validateKnownFields(object, "/response_format", fields)
}
