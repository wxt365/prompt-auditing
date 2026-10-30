package security

import (
	"fmt"
	"strconv"
	"strings"
)

func ExtractImageGeneration(body []byte) (Payload, error) {
	return extractPayloadWithOptions(body, validateImageFields, extractionOptions{images: true})
}

func ExtractImageEdit(body []byte) (Payload, error) {
	return extractPayloadWithOptions(body, func(root map[string]any) error {
		if err := validateImageFields(root); err != nil {
			return err
		}
		images, ok := root["images"].([]any)
		if !ok || len(images) == 0 || len(images) > 16 {
			return fmt.Errorf("/images 必须包含 1 至 16 个图片引用")
		}
		for index, image := range images {
			if err := validateImageReference(image, fmt.Sprintf("/images/%d", index)); err != nil {
				return err
			}
		}
		for _, key := range []string{"mask", "markup"} {
			if value, exists := root[key]; exists {
				if err := validateImageReference(value, "/"+key); err != nil {
					return err
				}
			}
		}
		return nil
	}, extractionOptions{images: true, imageEdit: true})
}

func validateImageFields(root map[string]any) error {
	prompt, ok := root["prompt"].(string)
	if !ok || strings.TrimSpace(prompt) == "" {
		return fmt.Errorf("/prompt 必须是非空字符串")
	}
	return validateKnownFields(root, "", map[string]valueValidator{
		"model": scalar(isString), "prompt": scalar(isString),
		"size": scalar(isString), "quality": scalar(isString),
		"background": scalar(isString), "output_format": scalar(isString),
		"response_format": scalar(isString), "moderation": scalar(isString),
		"input_fidelity": scalar(isString), "user": scalar(isString),
		"safety_identifier": scalar(isString), "stream": scalar(isBool),
		"n": scalar(isNumber), "output_compression": scalar(isNumber),
		"partial_images": scalar(isNumber),
	})
}

func isImageReferencePath(path string) bool {
	if path == "/mask" || path == "/markup" {
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 2 || parts[0] != "images" {
		return false
	}
	_, err := strconv.Atoi(parts[1])
	return err == nil
}

func validateImageReference(value any, path string) error {
	object, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("%s 必须是图片引用对象", path)
	}
	url, hasURL := object["image_url"]
	id, hasID := object["file_id"]
	if hasURL == hasID {
		return fmt.Errorf("%s 必须且只能包含 image_url 或 file_id 中的一项", path)
	}
	if hasURL {
		return validateImageURL(url, path+"/image_url")
	}
	if text, ok := id.(string); !ok || strings.TrimSpace(text) == "" {
		return fmt.Errorf("%s/file_id 必须是非空字符串", path)
	}
	return nil
}
