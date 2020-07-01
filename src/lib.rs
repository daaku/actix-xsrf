//! Middleware to provide XSRF protection.

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::HeaderValue;
use actix_web::http::{self, CookieBuilder};
use actix_web::HttpMessage;
use actix_web::{Error, HttpRequest};
use futures_util::future::{ok, FutureExt, LocalBoxFuture, Ready};
use std::convert::TryInto;
use std::task::{Context, Poll};
use xsrf::{CookieToken, RequestToken};

const MIDDLEWARE_MISSING: &str = "xsrf_token used without corresponding middleware";

pub trait RequestXSRF {
    fn xsrf_token(&self) -> RequestToken;
}

fn get_existing_request_token(req: &HttpRequest) -> Option<RequestToken> {
    let ext = req.extensions();
    ext.get::<ReqExt>()
        .expect(MIDDLEWARE_MISSING)
        .request_token
        .as_ref()
        .map(|rt| rt.clone())
}

fn ensure_cookie_token(req: &HttpRequest) {
    let cookie_name = {
        let ext = req.extensions();
        let re = ext.get::<ReqExt>().expect(MIDDLEWARE_MISSING);
        if re.cookie_token.is_some() {
            return;
        }
        re.cookie_name
    };

    let mut write_cookie = false;
    let ct = match req.cookie(cookie_name) {
        Some(cookie) => cookie.value().try_into().unwrap_or_else(|_| {
            write_cookie = true;
            CookieToken::new()
        }),
        None => {
            write_cookie = true;
            CookieToken::new()
        }
    };
    let mut ext = req.extensions_mut();
    let re = ext.get_mut::<ReqExt>().expect(MIDDLEWARE_MISSING);
    re.cookie_token = Some(ct);
    if write_cookie {
        re.write_cookie = write_cookie;
    }
}

impl RequestXSRF for HttpRequest {
    fn xsrf_token(&self) -> RequestToken {
        if let Some(rt) = get_existing_request_token(self) {
            return rt;
        }
        ensure_cookie_token(self);

        let mut ext = self.extensions_mut();
        let re = ext.get_mut::<ReqExt>().expect(MIDDLEWARE_MISSING);
        let ct = re.cookie_token.as_ref().unwrap();
        re.request_token = Some(ct.gen_req_token());
        return re.request_token.as_ref().unwrap().clone();
    }
}

struct ReqExt {
    cookie_name: &'static str,
    cookie_token: Option<CookieToken>,
    request_token: Option<RequestToken>,
    write_cookie: bool,
}

/// `Middleware` to clean request's URI, and redirect if necessary.
/// See module documenation for more.
#[derive(Clone)]
pub struct ProtectXSRF {
    cookie_name: &'static str,
}

impl<S, B> Transform<S> for ProtectXSRF
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = ProtectXSRFTransform<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ProtectXSRFTransform {
            config: self.clone(),
            service,
        })
    }
}

#[doc(hidden)]
pub struct ProtectXSRFTransform<S> {
    config: ProtectXSRF,
    service: S,
}

impl<S, B> Service for ProtectXSRFTransform<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        // TODO: check for token if not whitelisted method
        // TODO: issue token cookie, if one was used in the request
        // TODO: extension methods on request to get request token
        // TODO: allow bypassing check on certain paths

        {
            let mut ext = req.extensions_mut();
            ext.insert(ReqExt {
                cookie_name: self.config.cookie_name,
                cookie_token: None,
                request_token: None,
                write_cookie: false,
            });
        }

        let fut = self.service.call(req);
        async move {
            let res = fut.await;
            let mut res = match res {
                Err(err) => return Err(err),
                Ok(res) => res,
            };

            {
                let ext = res.request().extensions();
                let req_ext = ext.get::<ReqExt>().unwrap();
                if req_ext.write_cookie {
                    let cookie = CookieBuilder::new(
                        req_ext.cookie_name,
                        req_ext.cookie_token.as_ref().unwrap().to_string(),
                    )
                    .finish()
                    .to_string();
                    drop(ext);
                    res.headers_mut().append(
                        http::header::SET_COOKIE,
                        HeaderValue::from_str(&cookie).unwrap(),
                    );
                }
            }
            Ok(res)
        }
        .boxed_local()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtectXSRF, RequestXSRF};
    use actix_web::test::{call_service, init_service, TestRequest};
    use actix_web::{http, web, App, HttpRequest, HttpResponse, Responder};

    async fn echo_request_token1(req: HttpRequest) -> impl Responder {
        req.xsrf_token().to_string()
    }

    async fn echo_request_token2(req: HttpRequest) -> impl Responder {
        format!(
            "{}\n{}",
            req.xsrf_token().to_string(),
            req.xsrf_token().to_string()
        )
    }

    macro_rules! app {
        () => {
            init_service(
                App::new()
                    .wrap(ProtectXSRF { cookie_name: "x" })
                    .service(web::resource("/unused/").to(|| HttpResponse::Ok()))
                    .service(web::resource("/echo1/").to(echo_request_token1))
                    .service(web::resource("/echo2/").to(echo_request_token2)),
            )
            .await
        };
    }

    #[actix_rt::test]
    async fn test_no_cookie_unless_used() {
        let mut app = app!();
        let req = TestRequest::with_uri("/echo1/").to_request();
        let res = call_service(&mut app, req).await;
        assert!(&res
            .headers()
            .get(http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("x="));
    }
}
