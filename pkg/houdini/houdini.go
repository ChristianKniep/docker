package houdini // import "github.com/docker/docker/pkg/houdini"

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/docker/docker/pkg/ioutils"
	"github.com/sirupsen/logrus"
)

const maxBodySize = 1048576 // 1MB

//
func NewCtx(houdiniPlugins []Plugin, user, userAuthNMethod, requestMethod, requestURI string) *Ctx {
	return &Ctx{
		plugins:         houdiniPlugins,
		user:            user,
		userAuthNMethod: userAuthNMethod,
		requestMethod:   requestMethod,
		requestURI:      requestURI,
	}
}

// Ctx stores a single request-response interaction context
type Ctx struct {
	user            string
	userAuthNMethod string
	requestMethod   string
	requestURI      string
	plugins         []Plugin
	// authReq stores the cached request object for the current transaction
	authReq 		*Request
}

// ManipulateRequest authorized the request to the docker daemon using authZ plugins
func (ctx *Ctx) ManipulateRequest(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	var body []byte
	if sendBody(ctx.requestURI, r.Header) && r.ContentLength > 0 && r.ContentLength < maxBodySize {
		var err error
		body, r.Body, err = drainBody(r.Body)
		if err != nil {
			return r, err
		}
	}

	var h bytes.Buffer
	if err := r.Header.Write(&h); err != nil {
		return r, err
	}

	ctx.authReq = &Request{
		User:            ctx.user,
		UserAuthNMethod: ctx.userAuthNMethod,
		RequestMethod:   ctx.requestMethod,
		RequestURI:      ctx.requestURI,
		RequestBody:     body,
		RequestHeaders:  headers(r.Header),
	}

	if r.TLS != nil {
		for _, c := range r.TLS.PeerCertificates {
			pc := PeerCertificate(*c)
			ctx.authReq.RequestPeerCertificates = append(ctx.authReq.RequestPeerCertificates, &pc)
		}
	}

	for _, plugin := range ctx.plugins {
		logrus.Debugf("Manipulate request using plugin %s", plugin.Name())

		newR, err := plugin.ManipulateRequest(r)
		if err != nil {
			return r, fmt.Errorf("plugin %s failed with error: %s", plugin.Name(), err)
		}
		// In case no error occured we overwrite the old Req with the manipulated one
		r = newR
	}
	return r, nil
}



// drainBody dump the body (if its length is less than 1MB) without modifying the request state
func drainBody(body io.ReadCloser) ([]byte, io.ReadCloser, error) {
	bufReader := bufio.NewReaderSize(body, maxBodySize)
	newBody := ioutils.NewReadCloserWrapper(bufReader, func() error { return body.Close() })

	data, err := bufReader.Peek(maxBodySize)
	// Body size exceeds max body size
	if err == nil {
		logrus.Warnf("Request body is larger than: '%d' skipping body", maxBodySize)
		return nil, newBody, nil
	}
	// Body size is less than maximum size
	if err == io.EOF {
		return data, newBody, nil
	}
	// Unknown error
	return nil, newBody, err
}

// sendBody returns true when request/response body should be sent to AuthZPlugin
func sendBody(url string, header http.Header) bool {
	// Skip body for auth endpoint
	if strings.HasSuffix(url, "/auth") {
		return false
	}

	// body is sent only for text or json messages
	return header.Get("Content-Type") == "application/json"
}

// headers returns flatten version of the http headers excluding authorization
func headers(header http.Header) map[string]string {
	v := make(map[string]string)
	for k, values := range header {
		// Skip authorization headers
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "X-Registry-Config") || strings.EqualFold(k, "X-Registry-Auth") {
			continue
		}
		for _, val := range values {
			v[k] = val
		}
	}
	return v
}