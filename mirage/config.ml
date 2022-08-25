open Mirage

type paf = Paf
let paf = typ Paf

let paf_conf () =
  let packages = [ package "paf" ~sublibs:[ "mirage" ] ] in
  impl ~packages "Paf_mirage.Make" (time @-> tcpv4v6 @-> paf)

let uri =
  let doc = Key.Arg.info ~doc:"URI" [ "u"; "uri" ] in
  Key.(create "uri" Arg.(required string doc))

let mirror =
  foreign "Unikernel.Make"
    ~keys:[ Key.v uri ]
    ~packages:[ package "paf" ~min:"0.0.9" ; package "paf-cohttp" ~min:"0.0.7" ]
    (console @-> time @-> pclock @-> stackv4v6 @-> dns_client @-> paf @-> job)

let paf time stackv4v6 = paf_conf () $ time $ tcpv4v6_of_stackv4v6 stackv4v6

let stackv4v6 = generic_stackv4v6 default_network

let () = register "mirror"
    [ mirror $ default_console $ default_time $ default_posix_clock $ stackv4v6 $ generic_dns_client stackv4v6 $ paf default_time stackv4v6 ]
