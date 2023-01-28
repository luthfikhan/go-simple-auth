package helper

import "github.com/sirupsen/logrus"

type logger struct {
}

func (l *logger) Info(data map[string]any, message ...interface{}) {
	if message == nil {
		message = append(message, "Request Info")
	}

	go func() {
		logrus.WithFields(data).Info(message...)
	}()
}

func (l *logger) Error(data map[string]any, message ...interface{}) {
	if message == nil {
		message = append(message, "Request Error")
	}

	go func() {
		logrus.WithFields(data).Error(message...)
	}()
}

func (l *logger) Warn(data map[string]any, message ...interface{}) {
	if message == nil {
		message = append(message, "Request Warm")
	}

	go func() {
		logrus.WithFields(data).Warn(message...)
	}()
}

var Log = &logger{}
