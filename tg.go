package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func TgSetWebhook(url string, allowedupdates []string, secrettoken string) error {
	if DEBUG {
		log("DEBUG TgSetWebhook url==%s allowedupdates==%s secrettoken==%s", url, allowedupdates, secrettoken)
	}

	swreq := TgSetWebhookRequest{
		Url:            url,
		MaxConnections: TgWebhookMaxConnections,
		AllowedUpdates: allowedupdates,
		SecretToken:    secrettoken,
	}
	swreqjs, err := json.Marshal(swreq)
	if err != nil {
		return err
	}
	swreqjsBuffer := bytes.NewBuffer(swreqjs)

	var resp *http.Response
	tgapiurl := fmt.Sprintf("https://api.telegram.org/bot%s/setWebhook", TgToken)
	resp, err = http.Post(
		tgapiurl,
		"application/json",
		swreqjsBuffer,
	)
	if err != nil {
		return fmt.Errorf("apiurl:`%s` apidata:`%s` %v", tgapiurl, swreqjs, err)
	}

	var swresp TgSetWebhookResponse
	var swrespbody []byte
	swrespbody, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("io.ReadAll: %w", err)
	}
	err = json.NewDecoder(bytes.NewBuffer(swrespbody)).Decode(&swresp)
	if err != nil {
		return fmt.Errorf("json.Decoder.Decode: %w", err)
	}
	if !swresp.OK || !swresp.Result {
		return fmt.Errorf("apiurl:`%s` apidata:`%s` api response not ok: %+v", tgapiurl, swreqjs, swresp)
	}

	return nil
}

type TgSetWebhookRequest struct {
	Url            string   `json:"url"`
	MaxConnections int64    `json:"max_connections"`
	AllowedUpdates []string `json:"allowed_updates"`
	SecretToken    string   `json:"secret_token,omitempty"`
}

type TgSetWebhookResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Result      bool   `json:"result"`
}

func tglog(chatid int64, replyid int64, editid int64, msg string, args ...interface{}) (msgid int64, err error) {
	text := fmt.Sprintf(msg, args...)
	text = strings.NewReplacer(
		"(", "\\(",
		")", "\\)",
		"[", "\\[",
		"]", "\\]",
		"{", "\\{",
		"}", "\\}",
		"~", "\\~",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"!", "\\!",
		".", "\\.",
	).Replace(text)

	var reqjs []byte
	var tgurl string

	if editid == 0 {
		tgurl = fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TgToken)
		smreq := TgSendMessageRequest{
			ChatId:              chatid,
			ReplyToMessageId:    replyid,
			Text:                text,
			ParseMode:           TgParseMode,
			DisableNotification: TgDisableNotification,
		}
		reqjs, err = json.Marshal(smreq)
		if err != nil {
			return 0, err
		}
	} else {
		tgurl = fmt.Sprintf("https://api.telegram.org/bot%s/editMessageText", TgToken)
		emreq := TgEditMessageRequest{
			TgSendMessageRequest: TgSendMessageRequest{
				ChatId:              chatid,
				ReplyToMessageId:    replyid,
				Text:                text,
				ParseMode:           TgParseMode,
				DisableNotification: TgDisableNotification,
			},
			MessageId: editid,
		}
		reqjs, err = json.Marshal(emreq)
		if err != nil {
			return 0, err
		}
	}
	reqjsBuffer := bytes.NewBuffer(reqjs)

	var resp *http.Response
	resp, err = http.Post(
		tgurl,
		"application/json",
		reqjsBuffer,
	)
	if err != nil {
		return 0, fmt.Errorf("url==%v data==%v error: %v", tgurl, reqjs, err)
	}

	var smresp TgSendMessageResponse
	err = json.NewDecoder(resp.Body).Decode(&smresp)
	if err != nil {
		return 0, fmt.Errorf("%v", err)
	}
	if !smresp.OK {
		return 0, fmt.Errorf("apiurl==%v apidata==%v api response not ok: %+v", tgurl, reqjs, smresp)
	}

	return smresp.Result.MessageId, nil
}

type TgSendMessageRequest struct {
	ChatId              int64  `json:"chat_id"`
	ReplyToMessageId    int64  `json:"reply_to_message_id,omitempty"`
	Text                string `json:"text"`
	ParseMode           string `json:"parse_mode,omitempty"`
	DisableNotification bool   `json:"disable_notification"`
}

type TgSendMessageResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
	Result      struct {
		MessageId int64 `json:"message_id"`
	} `json:"result"`
}

type TgEditMessageRequest struct {
	TgSendMessageRequest
	MessageId int64 `json:"message_id"`
}

type TgUpdate struct {
	UpdateId    int64     `json:"update_id"`
	Message     TgMessage `json:"message"`
	ChannelPost TgMessage `json:"channel_post"`
}

type TgMessage struct {
	MessageId      int64  `json:"message_id"`
	From           TgUser `json:"from"`
	SenderChat     TgChat `json:"sender_chat"`
	Chat           TgChat `json:"chat"`
	Date           int64  `json:"date"`
	Text           string `json:"text"`
	ReplyToMessage struct {
		MessageId  int64  `json:"message_id"`
		From       TgUser `json:"from"`
		SenderChat TgChat `json:"sender_chat"`
		Chat       TgChat `json:"chat"`
		Date       int64  `json:"date"`
		Text       string `json:"text"`
	} `json:"reply_to_message"`
}

type TgUser struct {
	Id        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
}

type TgChat struct {
	Id    int64  `json:"id"`
	Title string `json:"title"`
	Type  string `json:"type"`
}
