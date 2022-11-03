open Mirage

type http_client = HTTP_client
let http_client = typ HTTP_client

let check =
  let doc =
    Key.Arg.info ~doc:"Only check the cache" ["check"]
  in
  Key.(create "check" Arg.(flag doc))

let verify_sha256 =
  let doc =
    Key.Arg.info ~doc:"Verify the SHA256 checksums of the cache contents, and \
                       re-build the other checksum caches."
      ["verify-sha256"]
  in
  Key.(create "verify-sha256" Arg.(flag doc))

let remote =
  let doc =
    Key.Arg.info
      ~doc:"Remote repository url, use suffix #foo to specify a branch 'foo': \
            https://github.com/ocaml/opam-repository.git"
      ["remote"]
  in
  Key.(create "remote" Arg.(opt string "https://github.com/ocaml/opam-repository.git#master" doc))

let parallel_downloads =
  let doc =
    Key.Arg.info
      ~doc:"Amount of parallel HTTP downloads"
      ["parallel-downloads"]
  in
  Key.(create "parallel-downloads" Arg.(opt int 20 doc))

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

let sectors_cache =
  let doc = "Number of sectors reserved for each checksum cache (md5, sha512)." in
  let doc = Key.Arg.info ~doc ["sectors-cache"] in
  Key.(create "sectors-cache" Arg.(opt int64 Int64.(mul 4L 2048L) doc))

let sectors_git =
  let doc = "Number of sectors reserved for git dump." in
  let doc = Key.Arg.info ~doc ["sectors-git"] in
  Key.(create "sectors-git" Arg.(opt int64 Int64.(mul 40L (mul 2L 1024L)) doc))

let ignore_local_git =
  let doc = "Ignore restoring locally saved git repository." in
  let doc = Key.Arg.info ~doc ["ignore-local-git"] in
  Key.(create "ignore-local-git" Arg.(flag doc))

let mirror =
  foreign "Unikernel.Make"
    ~keys:[ Key.v check ; Key.v verify_sha256 ; Key.v remote ;
            Key.v parallel_downloads ; Key.v hook_url ; Key.v tls_authenticator ;
            Key.v port ; Key.v sectors_cache ; Key.v sectors_git ;
            Key.v ignore_local_git ;
          ]
    ~packages:[
      package ~min:"0.3.0" ~sublibs:[ "mirage" ] "paf" ;
      package "h2" ;
      package "hex" ;
      package "httpaf" ;
      package ~pin:"git+https://git.robur.io/robur/git-kv.git#main" "git-kv" ;
      package ~min:"3.10.0" "git-paf" ;
      package "opam-file-format" ;
      package ~min:"2.2.0" ~sublibs:[ "gz" ] "tar" ;
      package ~min:"2.2.0" "tar-mirage" ;
      package "mirage-block-partition" ;
      package "oneffs" ;
    ]
    (block @-> time @-> pclock @-> stackv4v6 @-> git_client @-> http_client @-> job)

let stack = generic_stackv4v6 default_network

let dns = generic_dns_client stack

let tcp = tcpv4v6_of_stackv4v6 stack

let http_client =
  let packages =
    [ package "http-mirage-client" ] in
  let connect _ modname = function
    | [ _pclock; _tcpv4v6; ctx ] ->
      Fmt.str {ocaml|%s.connect %s|ocaml} modname ctx
    | _ -> assert false in
  impl ~packages ~connect "Http_mirage_client.Make"
    (pclock @-> tcpv4v6 @-> git_client @-> http_client)
(* XXX(dinosaure): [git_client] seems bad but it becames from a long discussion
   when a "mimic" device seems not accepted by everyone. We can copy [git_happy_eyeballs]
   and provide an [http_client] instead of a [git_client] but that mostly means that
   2 instances of happy-eyeballs will exists together which is not really good
   (it puts a pressure on the scheduler). *)

let git_client, http_client =
  let happy_eyeballs = git_happy_eyeballs stack dns (generic_happy_eyeballs stack dns) in
  merge_git_clients (git_tcp tcp happy_eyeballs)
    (git_http ~authenticator:tls_authenticator tcp happy_eyeballs),
  http_client $ default_posix_clock $ tcp $ happy_eyeballs

let program_block_size =
  let doc = Key.Arg.info [ "program-block-size" ] in
  Key.(create "program_block_size" Arg.(opt int 16 doc))

let block = block_of_file "tar"

let () = register "mirror"
    [ mirror $ block $ default_time $ default_posix_clock $ stack $ git_client $ http_client ]
