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
import stdlib.themes.bootstrap
import stdlib.widgets.bootstrap
import geeklist

WB = WBootstrap

/**
 * We don't want to publish these application keys, yet, they will be different for
 * each application that links into geeklist.
 * Ask for suitable keys or create some yourself on the Geeklist Website.
 **/
function getre(resource) {
  String.trim(Option.default({data:"",mimetype:""},Resource.export_data(resource)).data);
}

params = {
  // Callback address
  host:"http://localhost:8080",
  // Consumer data allocated to Geeklist OPA Test application
  consumer_key:getre(@static_resource("resources/consumer_key.txt")),
  consumer_secret:getre(@static_resource("resources/consumer_secret.txt"))
}

GL = Geeklist(params)

function get_avatar(option(string) avatar) {
  match (avatar) {
    case {some:avatar}: <img class="pull-right" src="{avatar}" alt="Geeklist" height="20" width="20"/>
    case {none}: <span class="icon icon-user pull-right"/>
  }
}

server function micro(_) {
  str = Dom.get_value(#micro);
  match (GL.create_micro(str)) {
    case {success:_}:
      Dom.set_value(#micro,"");
      message = WB.Message.make({block:{title:"Created micro:", description:<>{"\"{str}\""}</>}, actions:none, closable:true},
                                {success});
      #status = message;
    case {failure:f}:
      err = "{f}";
      message = WB.Message.make({block:{title:"Error:", description:<>{err}</>}, actions:none, closable:true}, {error});
      #status = message;
  }
}

function compose_xhtml((int n, string s), xhtml x) {
  <>{x}</>
  <+>
  <><span>{"{n+1}) {s}"}</span><br/></>
}

function decode(str) {
  str = String.replace("&quot;","\"",str);
  str = String.replace("&amp;","&",str);
  str = String.replace("&apos;","\'",str);
  str = String.replace("&lt;","<",str);
  str = String.replace("&gt;",">",str);
  str
}

function get_micros(_) {
  micros =
    match (GL.geek_screen_name()) {
      case {some:sn}:
        match (GL.list_micros({some:sn},[{count:5}])) {
          case {success:{json:{Record:[("total_micros",{Int:_tm}), ("micros",{List:l})]}}}:
            mcs = List.mapi(function (n, mic) {
                              match (mic) {
                                case {Record:r}:
                                  match (List.assoc("status",r)) {
                                    case {some:{String:status}}: (n, decode(status));
                                    default: (n, "No status");
                                  }
                                default: (n, "No status");
                              }
                            },l);
            (xhtml) List.fold(compose_xhtml,mcs,<></>);
          case {failure:f}:
            (xhtml) (<>{"{f}"}</>);
          default:
            (xhtml) (<>Bad reply</>);
        }
      case {none}: (<></>);
    };
  #micros = micros;
}

server function page(string err) {
  (authdrop, geeklist_logo) =
    if (GL.valid_credentials())
      ("Drop",<img class="pull-right" src="http://a3.twimg.com/profile_images/1564433929/face_normal"
                   alt="Geeklist" height="20" width="20"></img>)
    else ("Auth",<></>);
  avatar = get_avatar(GL.geek_avatar({small}));
  err = if (err == "") (<></>) else (<h2 style="color:red;">{err}</h2>);
  WBootstrap.Layout.fixed(
  <div class="main">
    <div class="well">
      <div class="row">
        <div class="span9">
          <h1>Test Geeklist API</h1><br/>
        </div>
      </div>
      {geeklist_logo}
      {avatar}
      <div>
        <a onclick={GL.authenticate({here},params.host,"status")} class="btn">{"{authdrop} here"}</a>
        <a onclick={GL.authenticate({popup:{width:800, height:400}},params.host,"status")} class="btn">{"{authdrop} popup"}</a>
      </div>
      <span>
        <label class="span2" for="micro">Micro:</label>
        <input class="span4" id="micro" type="text" value=""/>
        <a href="javascript:void(0)" class="btn" onclick={micro}>Create</a>
        <a href="javascript:void(0)" class="btn" onclick={get_micros}>Refresh</a>
      </span>
    </div>
    <div id="status" class="alert alert-info">{err}</div>
    <div>
      <h4>Last 5 micros</h4>
      <div id="micros" class="span8" onready={get_micros}></div>
    </div>
  </div>
  );
}

server function error_page((string error, (Dom.event -> void) close_window)) {
  actions = WB.Button.make({link:<>Close window</>, href:none, callback:close_window}, [{small}]);
  description =
    <div>
      <span>{error}</span>
    </div>
   message =
     WBootstrap.Message.make({block:{title:"Authentication error", ~description},
                             actions:some(actions), closable:false}, {error});
   WBootstrap.Layout.fixed(<div>{message}</div>);
}

server function login_page() {
  description =
    <div>
      <span>Authentication successful, this window should close automatically</span>
    </div>
   message =
     WBootstrap.Message.make({block:{title:"Login", ~description},
                             actions:none, closable:false}, {success});
   WBootstrap.Layout.fixed(<div>{message}</div>);
}

server function build_page(xhtml headers, xhtml page) {
  (resource) Resource.full_page_with_doctype("Geeklist Test", {html5}, page, headers, {success}, []);
}

server function main(page_type) {
  (resource) build_page(<></>,
                        match (page_type) {
                          case {main:err}: page(err);
                          case {login}: login_page();
                          case {~error}: error_page((string, (Dom.event -> void)) error);
                        });
}

function on_success() {
  match (GL.get_user()) {
    case {success:{json:{Record:user}}}: GL.set_geek(user);
    default: void;
  }
}

server dispatcher = parser {
  | "/favicon" (.*) -> @static_resource("favicon.gif")
  | result=GL.geeklist_uris(on_success) ->
    match (result) {
      case ({here},{ok}): main({main:""});
      case ({popup:_},{ok}): main({login});
      case ({here},{error:(err,_)}): main({main:err});
      case ({popup:_},{~error}): main({error:(string, (Dom.event -> void)) error});
    };
  | s=(.*) ->
    {
      s = Text.to_string(s);
      match (s) {
        default: main({main:""});
      }
    }
  }

Server.start(Server.http, [{custom:dispatcher} ])

// End of file geeklist_test.opa
