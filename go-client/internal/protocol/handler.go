package protocol

import (
	"fmt"
)

// HandlerFunc is the callback type for message handlers.
type HandlerFunc func(msg map[string]interface{}) (map[string]interface{}, error)

// MessageHandler routes incoming messages to registered callbacks.
type MessageHandler struct {
	handlers map[string]HandlerFunc
}

// NewMessageHandler creates a new handler.
func NewMessageHandler() *MessageHandler {
	return &MessageHandler{handlers: make(map[string]HandlerFunc)}
}

// Register registers a handler for a message type.
func (mh *MessageHandler) Register(msgType string, handler HandlerFunc) {
	mh.handlers[msgType] = handler
}

// Handle processes an incoming decrypted message.
func (mh *MessageHandler) Handle(msg map[string]interface{}) (map[string]interface{}, error) {
	msgType, _ := msg["type"].(string)
	if msgType == "" {
		return nil, fmt.Errorf("message missing 'type' field")
	}

	version, _ := msg["version"].(string)
	if version != ProtocolVersion {
		return ErrorMsg(0, VersionMismatch,
			fmt.Sprintf("Unsupported protocol version: %s", version)), nil
	}

	handler, ok := mh.handlers[msgType]
	if !ok {
		return nil, fmt.Errorf("unknown message type: %s", msgType)
	}

	return handler(msg)
}
