(* mirage >= 4.8.0 & < 4.9.0 *)
open Mirage

let mirror =
  main "Unikernel.Make"
    ~packages:[
      package ~min:"0.3.0" ~sublibs:[ "mirage" ] "paf" ;
      package "h2" ;
      package "ohex" ;
      package "httpaf" ;
      package ~max:"0.0.5" "git-kv" ;
      package ~min:"3.10.0" "git-paf" ;
      package "opam-file-format" ;
      package ~min:"3.0.0" ~sublibs:[ "gz" ] "tar" ;
      package ~min:"3.0.0" "tar-mirage" ;
      package ~max:"0.2.0" "mirage-block-partition" ;
      package "gpt" ;
      package "gptar" ~pin:"git+https://github.com/reynir/gptar.git" ;
      package "oneffs" ;
      package "digestif" ;
    ]
    (block @-> time @-> pclock @-> stackv4v6 @-> git_client @-> alpn_client @-> job)

let stack = generic_stackv4v6 default_network
let he = generic_happy_eyeballs stack
let dns = generic_dns_client stack he
let tcp = tcpv4v6_of_stackv4v6 stack
let block = block_of_file "tar"

let git_client, alpn_client =
  let git = mimic_happy_eyeballs stack he dns in
  merge_git_clients (git_ssh tcp git)
    (merge_git_clients (git_tcp tcp git)
      (git_http tcp git)),
  paf_client tcp (mimic_happy_eyeballs stack he dns)

let () = register "mirror"
  [ mirror $ block $ default_time $ default_posix_clock $ stack $ git_client $ alpn_client ]
