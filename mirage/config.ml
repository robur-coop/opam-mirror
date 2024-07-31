open Mirage

let setup = runtime_arg ~pos:__POS__ "Unikernel.K.setup"

let ssh_key =
  Runtime_arg.create ~pos:__POS__
    {|let open Cmdliner in
      let doc = Arg.info ~doc:"The private SSH key (rsa:<seed> or ed25519:<b64-key>)." ["ssh-key"] in
      Arg.(value & opt (some string) None doc)|}

let ssh_authenticator =
  Runtime_arg.create ~pos:__POS__
    {|let open Cmdliner in
      let doc = Arg.info ~doc:"SSH authenticator." ["ssh-auth"] in
      Arg.(value & opt (some string) None doc)|}

let ssh_password =
  Runtime_arg.create ~pos:__POS__
    {|let open Cmdliner in
      let doc = Arg.info ~doc:"The private SSH password." [ "ssh-password" ] in
      Arg.(value & opt (some string) None doc)|}

let tls_authenticator =
  Runtime_arg.create ~pos:__POS__
    {|let open Cmdliner in
      let doc = "TLS host authenticator. See git_http in lib/mirage/mirage.mli for a description of the format." in
      let doc = Arg.info ~doc ["tls-authenticator"] in
      Arg.(value & opt (some string) None doc)|}

let mirror =
  main "Unikernel.Make"
    ~runtime_args:[ setup ]
    ~packages:[
      package ~min:"0.3.0" ~sublibs:[ "mirage" ] "paf" ;
      package "h2" ;
      package "hex" ;
      package "httpaf" ;
      package ~max:"0.0.5" "git-kv" ;
      package ~min:"3.10.0" "git-paf" ;
      package "opam-file-format" ;
      package ~min:"2.2.0" ~sublibs:[ "gz" ] "tar" ~pin:"https://github.com/mirage/ocaml-tar.git#da4b1eb9fb903b3e6641b09e712156bd4a826f84";
      package ~min:"2.2.0" "tar-mirage" ~pin:"https://github.com/mirage/ocaml-tar.git#da4b1eb9fb903b3e6641b09e712156bd4a826f84";
      package ~max:"0.2.0" "mirage-block-partition" ;
      package "oneffs" ;
    ]
    (block @-> time @-> pclock @-> stackv4v6 @-> git_client @-> alpn_client @-> job)

let stack = generic_stackv4v6 default_network
let he = generic_happy_eyeballs stack
let dns = generic_dns_client stack he
let tcp = tcpv4v6_of_stackv4v6 stack
let block = block_of_file "tar"

let git_client, alpn_client =
  let git = mimic_happy_eyeballs stack he dns in
  merge_git_clients (git_ssh ~key:ssh_key ~authenticator:ssh_authenticator ~password:ssh_password tcp git)
    (merge_git_clients (git_tcp tcp git)
      (git_http ~authenticator:tls_authenticator tcp git)),
  paf_client tcp (mimic_happy_eyeballs stack he dns)

let () = register "mirror"
  [ mirror $ block $ default_time $ default_posix_clock $ stack $ git_client $ alpn_client ]
