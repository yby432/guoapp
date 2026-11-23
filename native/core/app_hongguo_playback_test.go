package core

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func TestHongguoPlaybackBody(t *testing.T) {
	compressed, err := hongguoPlaybackBody("7706514645208534041")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(plain, &body); err != nil {
		t.Fatal(err)
	}
	if body["dr_scene"] != "player" {
		t.Fatalf("wrong dr_scene: %v", body["dr_scene"])
	}
	mapped, _ := body["mixed_video_id_map"].(map[string]any)
	episodes, _ := mapped["1004"].([]any)
	if len(episodes) != 1 || episodes[0] != "7706514645208534041" {
		t.Fatalf("wrong mixed_video_id_map: %v", body["mixed_video_id_map"])
	}
	params, _ := body["biz_param"].(map[string]any)
	if params["device_level"] != float64(1) || params["video_platform"] != float64(1024) || params["need_all_video_definition"] != true {
		t.Fatalf("wrong biz_param: %v", params)
	}
}

func TestHongguoPlaybackModel(t *testing.T) {
	videoModel := `{"video_list":[{"main_url":"https://media.test/main.mp4","video_meta":{"codec_type":"h264","definition":"720p"}}],"video_duration":178}`
	grouped := map[string]any{"data": map[string]any{"1004": map[string]any{"7706514645208534041": map[string]any{"video_model": videoModel}}}}
	model, err := hongguoPlaybackModel(grouped, "7706514645208534041")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := model["video_list"]; !ok {
		t.Fatalf("grouped model missing video_list: %v", model)
	}
	legacy := map[string]any{"data": map[string]any{"video_model": map[string]any{"video_list": []any{}}}}
	if _, err := hongguoPlaybackModel(legacy, "7706514645208534041"); err != nil {
		t.Fatalf("legacy model rejected: %v", err)
	}
	if _, err := hongguoPlaybackModel(map[string]any{"data": map[string]any{}}, "7706514645208534041"); !errors.Is(err, errHongguoPlaybackEmpty) {
		t.Fatalf("empty model must report empty playback, got %v", err)
	}
}
