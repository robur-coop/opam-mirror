open Mirage

type paf = Paf
let paf = typ Paf

let paf_conf () =
  let packages = [ package "paf" ~sublibs:[ "mirage" ] ] in
  impl ~packages "Paf_mirage.Make" (time @-> tcpv4v6 @-> paf)

let remote =
  let doc = Key.Arg.info
      ~doc:"Remote repository url, use suffix #foo to specify a branch 'foo': \
            https://github.com/ocaml/opam-repository.git"
      ["remote"]
  in
  Key.(create "remote" Arg.(opt string "https://github.com/ocaml/opam-repository.git#master" doc))

let tls_authenticator =
  (* this will not look the same in the help printout *)
  let doc = "TLS host authenticator. See git_http in lib/mirage/mirage.mli for a description of the format."
  in
  let doc = Key.Arg.info ~doc ["tls-authenticator"] in
  Key.(create "tls-authenticator" Arg.(opt (some string) None doc))

let mirror =
  foreign "Unikernel.Make"
    ~keys:[ Key.v remote ; Key.v tls_authenticator ]
    ~packages:[
      package "paf" ~min:"0.0.9" ;
      package "paf-cohttp" ~min:"0.0.7" ;
      package ~min:"3.0.0" "irmin-mirage-git" ;
      package ~min:"3.7.0" "git-paf" ;
      package "opam-file-format" ;
    ]
    (kv_rw @-> time @-> pclock @-> stackv4v6 @-> dns_client @-> paf @-> git_client @-> job)

let paf time stackv4v6 = paf_conf () $ time $ tcpv4v6_of_stackv4v6 stackv4v6

let stack = generic_stackv4v6 default_network

let dns = generic_dns_client stack

let tcp = tcpv4v6_of_stackv4v6 stack

let git_client =
  let git = git_happy_eyeballs stack dns (generic_happy_eyeballs stack dns) in
  merge_git_clients (git_tcp tcp git)
    (git_http ~authenticator:tls_authenticator tcp git)

let program_block_size =
  let doc = Key.Arg.info [ "program-block-size" ] in
  Key.(create "program_block_size" Arg.(opt int 512 doc))

let kv_rw =
  let block = block_of_file "db" in
  chamelon ~program_block_size block

let () = register "mirror"
    [ mirror $ kv_rw $ default_time $ default_posix_clock $ stack $ dns $ paf default_time stack $ git_client ]
