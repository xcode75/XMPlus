package controller

import "github.com/xcode75/xcore/common/errors"

func newError(values ...interface{}) *errors.Error {
	return errors.New(values...)
}
