package middlewares

import (
	"errors"
	"strconv"

	"github.com/valyala/fasthttp"
)

type (
	HSTSConfiguration struct {
		MaxAge int
	}

	innerHSTS struct {
		strictTransportSecurity string
	}
)

var ErrHSTSInsecureConnection = errors.New("insecure connection")

func HSTS(configuration HSTSConfiguration) innerHSTS {
	return innerHSTS{strictTransportSecurity: "max-age=" + strconv.Itoa(configuration.MaxAge) + "; includeSubDomains; preload"}
}

func (HSTS innerHSTS) Handler(source fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(context *fasthttp.RequestCtx) {
		header := &context.Response.Header

		if context.IsTLS() {
			header.Set(fasthttp.HeaderStrictTransportSecurity, HSTS.strictTransportSecurity)

			if source != nil {
				source(context)
			}
		} else {
			uri := context.Request.URI()
			uri.SetScheme("https")

			header.SetStatusCode(fasthttp.StatusMovedPermanently)
			header.SetBytesV(fasthttp.HeaderLocation, uri.FullURI())

			context.SetBodyString(ErrHSTSInsecureConnection.Error())
		}
	}
}
