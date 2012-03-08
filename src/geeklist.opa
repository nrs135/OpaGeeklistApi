/*
    Copyright © 2011, 2012 MLstate

    This file is part of OPA.

    OPA is free software: you can redistribute it and/or modify it under the
    terms of the GNU Affero General Public License, version 3, as published by
    the Free Software Foundation.

    OPA is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for
    more details.

    You should have received a copy of the GNU Affero General Public License
    along with OPA.  If not, see <http://www.gnu.org/licenses/>.
*/
package geeklist

import stdlib.apis.common
import stdlib.apis.oauth
import stdlib.web.client

type Geeklist.query_params =
    // Pagination
    {int page}
 or {int count}

    // Create card
 or {string headline}

    // Create micro
 or {string typ}
 or {string in_reply_to}
 or {string status}

    // Create follow
 or {string user}
 or {string action}

    // Highfive (plus typ)
 or {string gfk}

type Geeklist.success =
    {RPC.Json.json json}
 or {ok}

type Geeklist.failure =
    {string string}
 or {WebClient.failure webclient}

type Geeklist.result = outcome(Geeklist.success, Geeklist.failure)

type Geeklist.credentials = {
  string access_token,
  string access_secret
}

type Geeklist.wtype =
    { here }
 or { {int width, int height} popup }

type Geeklist.data = {
  Geeklist.wtype wtype,
  string secret,
  string token,
  Geeklist.credentials credentials,
  list((string,RPC.Json.json)) geek
}

type Geeklist.params = {
  string host,
  string consumer_key,
  string consumer_secret
}

type Geeklist.popup_action =
  {login}

type Geeklist.popup_data = {
  Geeklist.wtype wtype,
  string after,
  Geeklist.popup_action action
}

type Geeklist.main_msg =
     { string after }
  or { close }

type Geeklist.srv_data = {
  Geeklist.popup_data data,
  option(channel(Geeklist.main_msg)) sess
}

type Geeklist.actsrv_msg =
    { string key,
      Geeklist.popup_data data,
      option(channel(Geeklist.main_msg)) sess }
 or { string key,
      (-> void) on_success }
 or { string key,
      void close }

#<Ifstatic:GEEKLIST_DEBUG>
private server module Cjlog {

  function vtcol(code) {
    match (code) {
      case {black}:   "30";
      case {red}:     "31";
      case {green}:   "32";
      case {yellow}:  "33";
      case {blue}:    "34";
      case {magenta}: "35";
      case {cyan}:    "36";
      case {white}:   "37";
    }
  }

  function coljlog(colour, msg) { jlog("[{vtcol(colour)}m{msg}[0m"); }
  function rjlog(msg) { coljlog({red},msg); }
  function gjlog(msg) { coljlog({green},msg); }
  function yjlog(msg) { coljlog({yellow},msg); }
  function bjlog(msg) { coljlog({blue},msg); }
  function mjlog(msg) { coljlog({magenta},msg); }
  function cjlog(msg) { coljlog({cyan},msg); }

}
#<End>

private server module Srv {

  function receive_actsrv(stringmap(Geeklist.srv_data) acts, Geeklist.actsrv_msg mess) {
    acts =
      match (mess) {
        case ~{key, data, sess}:
          //Cjlog.gjlog("receive_actsrv(data): key={key} data={data}");
          StringMap.add(key, ~{data, sess}, acts);
        case ~{key, on_success}:
          (acts,data_opt) = StringMap.extract(key, acts);
          match (data_opt) {
            case {some:~{data, sess}}:
              //Cjlog.gjlog("receive_actsrv(on_success): key={key} data={data} sess:{Option.is_some(sess)}");
              on_success();
              Option.iter(send(_, {after:data.after}), sess);
            case {none}:
              //Cjlog.gjlog("receive_actsrv(on_success): key={key} no data");
              void
          };
          acts;
        case {~key, close}:
          (acts,data_opt) = StringMap.extract(key, acts);
          match (data_opt) {
            case {some:~{data:_, sess}}: Option.iter(send(_, {close}), sess);
            case {none}: void
          };
          acts;
      };
    {set:acts}
  }

  function make_actsrv() { (channel('a)) Session.make_dynamic(StringMap.empty, receive_actsrv(_, _)); }

  (channel(Geeklist.actsrv_msg)) actsrv = make_actsrv()

}

module Geeklist(Geeklist.params params){

  (OAuth.parameters) oauth_params = {
    consumer_key      : params.consumer_key,
    consumer_secret   : params.consumer_secret,
    auth_method       : {HMAC_SHA1},
    request_token_uri : "http://sandbox-api.geekli.st/v1/oauth/request_token",
    authorize_uri     : "http://sandbox.geekli.st/oauth/authorize",
    access_token_uri  : "http://sandbox-api.geekli.st/v1/oauth/access_token",
    http_method       : {GET},
    inlined_auth      : false,
    custom_headers    : []
  }

  OA = OAuth(oauth_params)
  OA_POST = OAuth({oauth_params with http_method:(OAuth.method) {POST}})

  /**
   * For the moment we use UserContext to handle the interactions with Geeklist.
   * We should really setup callbacks as per SSO.
   **/
  private (Geeklist.credentials) blank_credentials = { access_token:"", access_secret:"" }

  (UserContext.t(Geeklist.data)) data =
    UserContext.make({wtype:{here}, secret:"", token:"", credentials:blank_credentials, geek:[]})

  server function get_auth() { UserContext.execute(function (data) { (data.wtype, data.token, data.secret); },data); }

  server function set_secret_token(Geeklist.wtype wtype, string secret, string token) {
    UserContext.change_or_destroy(function (data) { {some:{data with ~wtype, ~secret, ~token}}; },data);
  }

  server function get_geek() { UserContext.execute(function (data) { data.geek; },data); }

  server function set_geek(list((string,RPC.Json.json)) geek) {
    UserContext.change_or_destroy(function (data) { {some:{data with ~geek}}; },data);
  }

  server function get_credentials() { UserContext.execute(function (data) { data.credentials; },data); }

  server function set_credentials(Geeklist.credentials credentials) {
    UserContext.change_or_destroy(function (data) { {some:{data with ~credentials}}; },data);
  }

  server function valid_credentials() {
    credentials = get_credentials();
    (credentials.access_token != "" && credentials.access_secret != "")
  }

  server function geek_avatar(size) {
    (option(string)) match (List.assoc("avatar",get_geek())) {
      case {some:{Record:avatars}}:
        match (List.assoc(match (size) { case {small}: "small"; case {large}: "large"; },avatars)) {
          case {some:{String:small}}: {some:small};
          default: {none};
        };
      default: {none};
    };
  }

  server function geek_screen_name() {
    (option(string)) match (List.assoc("screen_name",get_geek())) {
      case {some:{String:screen_name}}: {some:screen_name};
      default: {none};
    }
  }

  private exposed function send_to_srv(msg) {
    //Cjlog.yjlog("send_to_srv: msg={msg}");
    send(Srv.actsrv, msg);
  }

  private client function post_redirect(uri) {
    //Cjlog.yjlog("post_redirect");
    form_id = Dom.fresh_id();
    form =
      <form id="{form_id}" method="post" action="{uri}">
        <input type="hidden" name="accept" value="Log In"/>
      </form>
    _x = Dom.put_at_end(Dom.select_raw_unsafe("body"), Dom.of_xhtml(form))
    Dom.trigger(#{form_id}, {submit})
  }

  private client function main_callback(window)(_, Geeklist.main_msg act) {
    //Cjlog.yjlog("main_callback");
    Option.iter(function (window) { Client.winclose({some:window}); },window);
    match (act) {
      case ~{after}: post_redirect(after);
      case {close}: void;
    };
    {stop}
  }

  private client function winopen(key, uri, width, height, data) {
    args = ["toolbar=no", "location=no", "directories=no", "status=no", "menubar=no", "width={width}", "height={height}"];
    window = Client.winopen(uri, {_blank}, args, false);
    sess = some(session(void, main_callback(some(window))));
    send_to_srv(~{key, data, sess})
    void
  }

  private client function cgoto(uri) { /*Cjlog.gjlog("cgoto:{uri}");*/ Client.goto(uri); }

  private function goto(wtype, after, string conf_uri) {
    //Cjlog.yjlog("goto: wtype={wtype} conf_uri={conf_uri}");
    match (HttpRequest.get_cookie()) {
      case {some:key}:
        data = ~{wtype, after, action:{login}};
        match (wtype) {
          case {here}: cgoto(conf_uri);
          case {popup:~{width, height}}: winopen(key, conf_uri, width, height, data);
        };
      case {none}:
        cgoto(conf_uri);
    }
  }

  private client function reload(string host) {
    location = Client.get_location();
    if (location.pathname == "/geeklist_callback")
      Client.goto(host)
    else
      Client.reload();
  }

  /**
   * An initial function to call authentication with Geeklist OAuth.
   * Trigger by a button or link or something.
   * Note that this is a toggle, if you are logged in it will log you out
   * and destroy the connection data.
   **/
  server function authenticate(wtype, after, err_id)(_) {
    if (valid_credentials()) {
      set_credentials(blank_credentials);
      set_geek([]);
      reload(after);
    } else
      match (OA.get_request_token("{params.host}/geeklist_callback")) {
        case {success:request}:
          conf_uri = OA.build_authorize_url(request.token);
          set_secret_token(wtype, request.secret, request.token);
          goto(wtype, after, conf_uri);
        case {error:e}:
          //Cjlog.rjlog("OAuth error: \"{e}\"");
          if (err_id != "") #{err_id} = <div><span>{"OAuth error: \"{e}\""}</span></div>;
      }
  }

  /**
   * Return the final access key granted by Geeklist.
   **/
  private server function access_token(string token, string secret, string verifier) {
    match ((token, secret, verifier)) {
      case ("",_,_): {error:"Not authenticated"};
      case (_,"",_): {error:"Not authenticated"};
      case (_,_,""): {error:"Not authenticated"};
      case (token, secret, verifier): OA.get_access_token(token, secret, verifier);
    }
  }

  private function make_error(Geeklist.wtype wtype, string error) {
    (wtype,
     {error:(error,
             function (_) {
               match (HttpRequest.get_cookie()) {
                 case {some:key}: send(Srv.actsrv, ~{key, close:void});
                 case {none}: void;
               }
             })})
  }

  /**
   * A parser which you can add to your server's input parser to handle the callbacks.
   **/
  server function geeklist_uris(on_success) {
    parser {
    | "/geeklist_callback?" token=(.*) ->
      match (OA.connection_result(Text.to_string(token))) {
        case {success:~{token, secret:_, verifier}}:
          (wtype, id_token, secret) = get_auth();
          //Cjlog.bjlog("geeklist_uris: wtype={wtype}");
          if (id_token == token) {
            match (access_token(token, secret, verifier)) {
            //match ({error:"test error"}) {
              case {~error}:
                //Cjlog.rjlog("Authentication failure: {error}");
                make_error(wtype,"Authentication failure: {error}");
              case {success:access}:
                set_credentials({access_token:access.token, access_secret:access.secret});
                match (wtype) {
                  case {here}:
                    on_success();
                  case {popup:_}:
                    match (HttpRequest.get_cookie()) {
                      case {some:key}:
                        //Cjlog.cjlog("geeklist_callback: key={key}");
                        send(Srv.actsrv, ~{key, on_success})
                      case {none}: void;
                    }; 
                };
                (wtype,{ok});
            };
          } else {
            if (id_token != "") {
              //Cjlog.rjlog("Token mismatch: \"{id_token}\" vs. \"{token}\"");
              make_error(wtype,"Token mismatch: \"{id_token}\" vs. \"{token}\"");
            } else ({here},{ok})
          }
        case {~error}:
          //Cjlog.rjlog("Authentication failure: {error}");
          make_error({here},"Authentication failure: {error}");
      };
    }
  }

  private function dig(RPC.Json.json json) {
    (outcome(Geeklist.success,string)) match (json) {
      case {Record:[("status", {String:"error"}), ("error", {String:err})]}: {failure:err};
      case {Record:[("status", {String:"ok"}), ("data", data)]}: {success:{json:data}};
      case {Record:[("status", {String:"ok"})]}: {success:{ok}};
      default: {failure:"no data {json}"};
    }
  }

  function geek(OA, list(string) path, list(Geeklist.query_params) params, Geeklist.credentials credentials) {
    params =
      List.map(function (qp) {
                 match (qp) {
                   case {~page}: ("page",int_to_string(page));
                   case {~count}: ("count",int_to_string(count));
                   case {~headline}: ("headline",headline);
                   case {~typ}: ("type",typ);
                   case {~in_reply_to}: ("in_reply_to",in_reply_to);
                   case {~status}: ("status",status);
                   case {~user}: ("user",user);
                   case {~action}: ("action",action);
                   case {~gfk}: ("gfk",gfk);
                 }
               },params);
    uri = "http://sandbox-api.geekli.st/v1/"^(String.concat("/",path));
    //jlog("uri={Uri.to_string(uri)}");
    (Geeklist.result) match (OA.get_protected_resource_2(uri,params,credentials.access_token,credentials.access_secret)) {
      case {failure:f}: {failure:{webclient:f}};
      case {success:result}:
        //jlog("result:{result}");
        match (Json.of_string(result.content)) {
          case {some:json}:
            match (dig(json)) {
              case {success:result}: {success:result};
              case {failure:f}: {failure:{string:f}};
            };
          case {none}: {failure:{string:"No JSON found"}};
        };
    }
  }

  /**
   * The low-level calls.  You can build any parameters with these.
   **/
  function get0(list(string) path, list(Geeklist.query_params) params, Geeklist.credentials credentials) {
    geek(OA, path, params, credentials)
  }

  function get(list(string) path, list(Geeklist.query_params) params) {
    credentials = get_credentials();
    get0(path, params, credentials)
  }

  function post0(list(string) path, list(Geeklist.query_params) params, Geeklist.credentials credentials) {
    geek(OA_POST, path, params, credentials)
  }

  function post(list(string) path, list(Geeklist.query_params) params) {
    credentials = get_credentials();
    post0(path, params, credentials)
  }

  private function not_authenticated() {
    (Geeklist.result) {failure:{string:"Not authenticated"}}
  }

  private function check_auth(fn) {
    (Geeklist.result) if (valid_credentials()) {
      fn();
    } else
      not_authenticated()
  }

  private function pag_opts(opts) {
    List.filter(function (opt) { match (opt) { case {page:_}: true; case {count:_}: true; default: false; } },opts)
  }

  /**
   * The main exported functions: as per the python API.
   **/

  function get_user() { check_auth(function () { get(["user"],[]) }); }
  function card(id) { check_auth(function () { get(["cards",id],[]); }) }
  function create_card(headline) { check_auth(function () { post(["cards"],[{~headline}]); }) }
  function micro(id) { check_auth(function () { get(["micros",id],[]); }) }
  function create_micro(string status) { check_auth(function () { post(["micros"],[{~status}]) }); }
  function reply_to_micro(string in_reply_to, string status) {
    check_auth(function () { post(["micros"],[{~status}, {typ:"micro"}, {~in_reply_to}]) });
  }
  function reply_to_card(string in_reply_to, string status) {
    check_auth(function () { post(["micros"],[{~status}, {typ:"card"}, {~in_reply_to}]) });
  }
  function follow(string user) { check_auth(function () { post(["follow"],[{~user}, {action:"follow"}]) }); }
  function unfollow(string user) { check_auth(function () { post(["follow"],[{~user}]) }); }
  function list_items(what, user, opts) {
    path =
      match (user) {
        case {some:user}: ["users",user,what];
        case {none}: ["user",what];
      };
    check_auth(function () { get(path,pag_opts(opts)); })
  }
  function list_cards(user, opts) { list_items("cards", user, opts); }
  function list_micros(user, opts) { list_items("micros", user, opts); }
  function list_followers(user, opts) { list_items("followers", user, opts); }
  function list_following(user, opts) { list_items("following", user, opts); }
  function list_activity(user, opts) {
    path =
      match (user) {
        case {all}: ["activity"];
        case {some:user}: ["users",user,"activity"];
        case {none}: ["user","activity"];
      };
    check_auth(function () { get(path,pag_opts(opts)); })
  }
  function highfive(typ, gfk) { check_auth(function () { post(["highfive"],[{~typ},{~gfk}]) }); }
  function highfive_card(gfk) { highfive("card",gfk); }
  function highfive_micro(gfk) { highfive("micro",gfk); }

}

