extern crate iron;
extern crate router;
extern crate logger;
extern crate handlebars_iron;
extern crate staticfile;
extern crate mount;
extern crate cookie;
extern crate oven;
extern crate urlencoded;
extern crate url;
extern crate persistent;
extern crate rand;
extern crate chrono;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use iron::prelude::*;
use iron::{Url, status};
use iron::modifiers::Redirect;

use router::Router;

use logger::Logger;

use handlebars_iron::{HandlebarsEngine, Template};

use mount::Mount;

use staticfile::Static;

use std::path::Path;

use std::collections::BTreeMap;

use oven::prelude::*;
use cookie::Cookie;

use std::io::Read as StdRead;

use urlencoded::UrlEncodedBody;

use rand::Rng;

use persistent::*;

use chrono::{DateTime, UTC};

// Here is some code to look at:
//
// https://github.com/brson/taskcluster-crater/blob/master/rs/crater-web/main.rs
//
// https://github.com/OsnaCS/uosql-server/blob/master/src/webclient/main.rs
//
// https://github.com/sunng87/handlebars-iron
//
// https://github.com/blackjune/blog/blob/master/src/main.rs
//
// Implements a session middleware:
// https://github.com/pikajude/jude-web.rs/blob/master/src/middleware/session/mod.rs

//----------------------------------------------------------------------------

#[derive(Debug)]
pub enum WebError {
    ErrorPersistent(persistent::PersistentError),
    ErrorStd(Box<Error + Send>),
    ErrorString(String)
}

impl Error for WebError {
    fn description(&self) -> &str {
        match *self {
            WebError::ErrorPersistent(ref e) => e.description(),
            WebError::ErrorStd(ref e) => e.description(),
            WebError::ErrorString(ref e) => e
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            WebError::ErrorStd(ref e) => Some(&** e),
            _ => None
        }
    }
}

impl From<persistent::PersistentError> for WebError {
    fn from(e: persistent::PersistentError) -> WebError {
        WebError::ErrorStd(Box::new(e))
    }
}

impl From<urlencoded::UrlDecodingError> for WebError {
    fn from(e: urlencoded::UrlDecodingError) -> WebError {
        WebError::ErrorStd(Box::new(e))
    }
}

impl Display for WebError {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        f.write_str(self.description())
    }
}

impl From<WebError> for IronError {
    fn from(e: WebError) -> IronError {
        IronError::new(e, status::InternalServerError)
    }
}

impl From<String> for WebError {
    fn from(e: String) -> WebError {
        WebError::ErrorString(e)
    }
}

impl<T> From<std::sync::PoisonError<T>> for WebError {
    fn from(e: std::sync::PoisonError<T>) -> WebError {
        WebError::ErrorString("poisoned lock".into())
    }
}

//----------------------------------------------------------------------------

#[derive(Copy, Clone)]
struct SessionType;

#[derive(Debug, Clone)]
struct SessionData {
    username: String,
    login_time: DateTime<UTC>
}

struct Sessions(BTreeMap<String, SessionData>);

static SESSION_COOKIE : &'static str = "_SESSION";

impl iron::typemap::Key for SessionType {
    type Value = Sessions;
}

pub fn absolute_url_from_path(request: &Request, path: Vec<String>) -> url::Url {
    let mut url = request.url.clone().into_generic_url();
    match url.scheme_data {
        url::SchemeData::Relative(ref mut rsd) => {
            rsd.path = path
        },
        _ => panic!("This is supposed to be a HTTP URL.")
    }
    url.query = None;
    url.fragment = None;
    url
}

fn get_session(req: &mut Request) -> IronResult<Option<SessionData>> {
    let session_key = match req.get_cookie(SESSION_COOKIE) {
        Some(cookie) => cookie.value.clone(),
        None => {
            return Ok(None);
        }
    };

    let session_type = try!(req.get::<persistent::State<SessionType>>().map_err(|e| WebError::from(e)));
   
    let sessions = try!(session_type.read().map_err(|e| WebError::from(e)));
    match sessions.0.get(&session_key) {
        Some(v) => Ok(Some(v.clone())),
        None => Ok(None)
    }
}

fn page_index(req: &mut Request) -> IronResult<Response> {
    let mut data: BTreeMap<String, String> = BTreeMap::new();

    let session = try!(get_session(req));
    if let Some(s) = session {
        println!("page_index has session: {:?}", s);
        data.insert("username".into(), s.username);
    }

    let mut resp = Response::new();
    resp.set_mut(Template::new("index", data)).set_mut(status::Ok);
    Ok(resp)
}

fn page_login(_req: &mut Request) -> IronResult<Response> {
    let mut resp = Response::new();
    resp.set_mut(Template::new("login", BTreeMap::<String, String>::new())).set_mut(status::Ok);
    Ok(resp)
}

fn page_logout(req: &mut Request) -> IronResult<Response> {
    let session_key = match req.get_cookie(SESSION_COOKIE) {
        Some(cookie) => cookie.value.clone(),
        None => String::new()
    };
    let session_type = try!(req.get::<persistent::State<SessionType>>().map_err(|e| WebError::from(e)));
   
    match session_type.write() {
        Ok(ref mut guard) => {
            let _ = guard.0.remove(&session_key);
        },
        Err(err) => { return Err(IronError::from(WebError::from(err))); }
    };

    let redirect_url = Redirect(iron::Url::from_generic_url(absolute_url_from_path(req, Vec::new())).unwrap());
    return Ok(Response::with((status::Found, redirect_url)));
}

fn extract_credentials(query_map: &urlencoded::QueryMap) -> Option<(String, String)> {
    let user = query_map.get("username".into()).and_then({
        |values| match values.len() {
            1 => Some(values[0].clone()),
            _ => None
        }});
    let pass = query_map.get("password".into()).and_then({
        |values| match values.len() {
            1 => Some(values[0].clone()),
            _ => None
        }});
    match (user, pass) {
        (Some(user), Some(pass)) => Some((user, pass)),
        _ => None
    }
}

fn authenticate_user(username: &str, password: &str) -> bool {
    username == "thorben".to_string() && password == "test".to_string()
}

fn try_login(req: &mut Request) -> IronResult<Response> {
    let (username, password) = {
        let query_map = try!(req.get_ref::<UrlEncodedBody>().map_err(|e| WebError::from(e)));
       
        // FIXME: How to write this error:
        // try!(extract_credentials(query_map)
        //     .ok_or(IronError::from(WebError::from("could not extract credentials".into()))));
        extract_credentials(query_map).unwrap()
    };

    if !authenticate_user(&username, &password) {
        let mut resp = Response::new();
        let data: BTreeMap<String, String> = BTreeMap::new();
        resp.set_mut(Template::new("login", data)).set_mut(status::Ok);
        return Ok(resp);
    }

    println!("Login successful");
    let session_key = rand::thread_rng().gen_ascii_chars().take(32).collect::<String>();

    let x = try!(req.get::<persistent::State<SessionType>>().map_err(|e| WebError::from(e)));
    let mut sessions = try!(x.write().map_err(|e| WebError::from(e)));
    let session_data = SessionData {
        username: username.to_owned(),
        login_time: UTC::now()
    };
    (*sessions).0.insert(session_key.clone(), session_data);

    let r = Vec::new();
    let rr = Redirect(iron::Url::from_generic_url(absolute_url_from_path(&req, r)).unwrap());
    let mut resp = Response::with((status::Found, rr));
    resp.set_cookie(Cookie::new(SESSION_COOKIE.to_string(), session_key.to_owned()));
    return Ok(resp);
}

fn main() {
    let mut router = Router::new();

    router.get("/", page_index);

    router.get("/login", page_login);
    router.post("/login", try_login);
    router.get("/logout", page_logout);

    let (logger_before, logger_after) = Logger::new(None);

    let mut chain = Chain::new(router);

    let template_engine = HandlebarsEngine::new("./templates/", ".hbs");
    
    chain.link_before(logger_before);

    chain.link(oven::new("MAKE_THIS_A_SECRET_KEY_LATER".into()));

    let initial_sessions : Sessions = Sessions(BTreeMap::new());
    chain.link(persistent::State::<SessionType>::both(initial_sessions));

    chain.link_after(template_engine);
    chain.link_after(logger_after);

    let mut mount = Mount::new();
    mount
        .mount("/", chain)
        .mount("/css", Static::new(Path::new("public/css")))
        .mount("/img", Static::new(Path::new("public/img")))
        .mount("/js", Static::new(Path::new("public/js")));

    Iron::new(mount).http("localhost:3000").unwrap();
}
