package security

import (
	"encoding/json"
	"fmt"
)

// 登记表以 Codex 0.144.5 契约样本为基线；未知协议对象必须失败关闭。
func validateRegisteredStructure(root map[string]any) error {
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
				"effort": scalar(isString), "summary": scalar(isString),
			})
		case "text":
			err = validateText(value)
		case "stream_options":
			err = validateObject(value, "/stream_options", map[string]valueValidator{
				"include_obfuscation": scalar(isBool),
			})
		case "client_metadata", "metadata":
			err = validateScalarMap(value, "/"+key)
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
		if !ok {
			return fmt.Errorf("%s/type 必须是字符串", path)
		}
		var fields map[string]valueValidator
		switch typeName {
		case "message":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"role": scalar(isString), "content": validateContent,
			}
		case "function_call_output":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"call_id": scalar(isString), "output": validateContent,
			}
		case "function_call":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"call_id": scalar(isString), "name": scalar(isString), "arguments": scalar(isString),
			}
		case "reasoning":
			fields = map[string]valueValidator{
				"type": scalar(isString), "id": scalar(isString), "status": scalar(isString),
				"encrypted_content": scalar(isString), "summary": validateSummary,
			}
		default:
			return fmt.Errorf("%s/type 未登记: %s", path, typeName)
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
		if !ok || (typeName != "input_text" && typeName != "output_text") {
			return fmt.Errorf("%s/type 未登记", itemPath)
		}
		fields := map[string]valueValidator{"type": scalar(isString), "text": scalar(isString)}
		if typeName == "output_text" {
			fields["annotations"] = validateEmptyArray
		}
		if err := validateKnownFields(object, itemPath, fields); err != nil {
			return err
		}
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
		if !ok || object["type"] != "summary_text" {
			return fmt.Errorf("%s 必须是 summary_text 对象", itemPath)
		}
		if err := validateKnownFields(object, itemPath, map[string]valueValidator{
			"type": scalar(isString), "text": scalar(isString),
		}); err != nil {
			return err
		}
	}
	return nil
}

func validateTools(value any) error {
	items, ok := value.([]any)
	if !ok {
		return fmt.Errorf("/tools 必须是数组")
	}
	for index, item := range items {
		path := fmt.Sprintf("/tools/%d", index)
		object, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%s 必须是对象", path)
		}
		var fields map[string]valueValidator
		switch object["type"] {
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
			return fmt.Errorf("%s/type 未登记", path)
		}
		if err := validateKnownFields(object, path, fields); err != nil {
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
		return fmt.Errorf("%s/type 未登记: %s", path, typeName)
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
			} else if typeName != "text" {
				return fmt.Errorf("%s/type 未登记: %s", path, typeName)
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
	if !ok || object["type"] != "function" {
		return fmt.Errorf("/tool_choice 必须是字符串或 function 对象")
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

func validateEmptyArray(value any, path string) error {
	items, ok := value.([]any)
	if !ok || len(items) != 0 {
		return fmt.Errorf("%s 仅支持空数组", path)
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
			return fmt.Errorf("%s/%s 未登记", path, key)
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
	return fmt.Errorf("%s 类型未登记", path)
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
