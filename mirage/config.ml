open Mirage

type http_client = HTTP_client
let http_client = typ HTTP_client

let key_hex =
  let doc =
    Key.Arg.info
      ~doc:"File system keys should be stored as human-readable (hex) characters"
      ["key-hex"]
  in
  Key.(create "key-hex" Arg.(flag doc))

let check =
  let doc =
    Key.Arg.info
      ~doc:"Only check the cache"
      ["check"]
  in
  Key.(create "check" Arg.(flag doc))

let remote =
  let doc =
    Key.Arg.info
      ~doc:"Remote repository url, use suffix #foo to specify a branch 'foo': \
            https://github.com/ocaml/opam-repository.git"
      ["remote"]
  in
  Key.(create "remote" Arg.(opt string "https://github.com/ocaml/opam-repository.git#master" doc))

let hook_url =
  let doc =
    Key.Arg.info
      ~doc:"URL to conduct an update of the git repository" ["hook-url"]
  in
  Key.(create "hook-url" Arg.(opt string "update" doc))

let port =
  let doc = Key.Arg.info ~doc:"HTTP listen port." ["port"] in
  Key.(create "port" Arg.(opt int 80 doc))

let tls_authenticator =
  (* this will not look the same in the help printout *)
  let doc = "TLS host authenticator. See git_http in lib/mirage/mirage.mli for a description of the format."
  in
  let doc = Key.Arg.info ~doc ["tls-authenticator"] in
  Key.(create "tls-authenticator" Arg.(opt (some string) None doc))

let mirror =
  foreign "Unikernel.Make"
    ~keys:[ Key.v key_hex ; Key.v check ; Key.v remote ; Key.v hook_url ; Key.v tls_authenticator ; Key.v port ]
    ~packages:[
      package ~min:"0.1.0" ~sublibs:[ "mirage" ] "paf" ;
      package "h2" ;
      package "httpaf" ;
      package ~min:"3.0.0" "irmin-mirage-git" ;
      package ~min:"3.7.0" "git-paf" ;
      package "opam-file-format" ;
      package ~min:"2.1.0" ~sublibs:[ "gz" ] "tar" ;
    ]
    (kv_rw @-> time @-> pclock @-> stackv4v6 @-> git_client @-> http_client @-> job)

let stack = generic_stackv4v6 default_network

let dns = generic_dns_client stack

let tcp = tcpv4v6_of_stackv4v6 stack

let http_client =
  let connect _ modname = function
    | [ _time; _pclock; _tcpv4v6; ctx ] ->
      Fmt.str {ocaml|%s.connect %s|ocaml} modname ctx
    | _ -> assert false in
  impl ~connect "Http_mirage_client.Make"
    (time @-> pclock @-> tcpv4v6 @-> git_client @-> http_client)
(* XXX(dinosaure): [git_client] seems bad but it becames from a long discussion
   when a "mimic" device seems not accepted by everyone. We can copy [git_happy_eyeballs]
   and provide an [http_client] instead of a [git_client] but that mostly means that
   2 instances of happy-eyeballs will exists together which is not really good
   (it puts a pressure on the scheduler). *)

let git_client, http_client =
  let happy_eyeballs = git_happy_eyeballs stack dns (generic_happy_eyeballs stack dns) in
  merge_git_clients (git_tcp tcp happy_eyeballs)
    (git_http ~authenticator:tls_authenticator tcp happy_eyeballs),
  http_client $ default_time $ default_posix_clock $ tcp $ happy_eyeballs

let program_block_size =
  let doc = Key.Arg.info [ "program-block-size" ] in
  Key.(create "program_block_size" Arg.(opt int 16 doc))

(*
let kv_rw =
  let block = block_of_file "db" in
  chamelon ~program_block_size block
*)

let kv_rw = direct_kv_rw "/tmp/mirror"

let () = register "mirror"
    [ mirror $ kv_rw $ default_time $ default_posix_clock $ stack $ git_client $ http_client ]
