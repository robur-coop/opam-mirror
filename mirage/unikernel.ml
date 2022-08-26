module type DNS = sig
  type t

  val gethostbyname : t -> [ `host ] Domain_name.t ->
    (Ipaddr.V4.t, [> `Msg of string ]) result Lwt.t
end

open Lwt.Infix

let argument_error = 64

module Make
  (KV : Mirage_kv.RW)
  (Time : Mirage_time.S)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Tcpip.Stack.V4V6)
  (Dns : DNS) (* XXX(dinosaure): ask @hannesm to provide a signature. *)
  (Paf : Paf_mirage.S with type stack = Stack.TCP.t and type ipaddr = Ipaddr.t)
  (_ : sig end) = struct

  module Store = Irmin_mirage_git.Mem.KV.Make(Irmin.Contents.String)
  module Sync = Irmin.Sync.Make(Store)

  module Client = Paf_cohttp
  module Nss = Ca_certs_nss.Make(Pclock)

  let authenticator = Result.get_ok (Nss.authenticator ())
  let default_tls_cfg = Tls.Config.client ~authenticator ()

  let stack = Mimic.make ~name:"stack"
  let tls = Mimic.make ~name:"tls"

  let with_stack v ctx = Mimic.add stack (Stack.tcp v) ctx

  let with_tcp ctx =
    let k scheme stack ipaddr port =
      match scheme with
      | `HTTP -> Lwt.return_some (stack, ipaddr, port)
      | _ -> Lwt.return_none
    in
    Mimic.(fold Paf.tcp_edn Fun.[ req Client.scheme
                                ; req stack
                                ; req Client.ipaddr
                                ; dft Client.port 80 ] ~k ctx)

  let with_tls ctx =
    let k scheme domain_name cfg stack ipaddr port =
      match scheme with
      | `HTTPS -> Lwt.return_some (domain_name, cfg, stack, ipaddr, port)
      | _ -> Lwt.return_none
    in
    Mimic.(fold Paf.tls_edn Fun.[ req Client.scheme
                                ; opt Client.domain_name
                                ; dft tls default_tls_cfg
                                ; req stack
                                ; req Client.ipaddr
                                ; dft Client.port 443 ] ~k ctx)

  let dns = Mimic.make ~name:"dns"

  let with_dns v ctx = Mimic.add dns v ctx
  let with_sleep ctx = Mimic.add Paf_cohttp.sleep Time.sleep_ns ctx

  let with_resolv ctx =
    let k dns domain_name =
      Dns.gethostbyname dns domain_name >>= function
      | Ok ipv4 -> Lwt.return_some (Ipaddr.V4 ipv4)
      | _ -> Lwt.return_none in
    Mimic.(fold Client.ipaddr Fun.[ req dns; req Client.domain_name ] ~k ctx)

  module SM = Map.Make(String)

  module HM = Map.Make(struct
      type t = Mirage_crypto.Hash.hash
      let compare = compare (* TODO remove polymorphic compare *)
    end)

  let hash_to_string = function
    | `MD5 -> "md5"
    | `SHA1 -> "sha1"
    | `SHA224 -> "sha224"
    | `SHA256 -> "sha256"
    | `SHA384 -> "sha384"
    | `SHA512 -> "sha512"

  let hex_to_string h =
    let `Hex h = Hex.of_string h in
    h

  let hex_of_string s =
    match Hex.to_string (`Hex s) with
    | d -> Ok d
    | exception Invalid_argument err -> Error (`Msg err)

  let hm_to_s hm =
    HM.fold (fun h v acc ->
        hash_to_string h ^ "=" ^ hex_to_string v ^ "\n" ^ acc)
      hm ""

  module Git = struct
    let decompose_git_url () =
      match String.split_on_char '#' (Key_gen.remote ()) with
      | [ url ] -> url, None
      | [ url ; branch ] -> url, Some branch
      | _ ->
        Logs.err (fun m -> m "expected at most a single # in remote");
        exit argument_error

    let connect ctx =
      let uri, branch = decompose_git_url () in
      let config = Irmin_mem.config () in
      Store.Repo.v config >>= fun r ->
      (match branch with
       | None -> Store.main r
       | Some branch -> Store.of_branch r branch) >|= fun repo ->
      Logs.info (fun m -> m "connected to %s (branch %s)"
                    uri (Option.value ~default:"main" branch));
      repo, Store.remote ~ctx uri

    let pull store upstream =
      Logs.info (fun m -> m "pulling from remote!");
      Sync.pull ~depth:1 store upstream `Set >|= fun r ->
      match r with
      | Ok (`Head _ as s) -> Ok (Fmt.str "pulled %a" Sync.pp_status s)
      | Ok `Empty -> Error (`Msg "pulled empty repository")
      | Error (`Msg e) -> Error (`Msg ("pull error " ^ e))
      | Error (`Conflict msg) -> Error (`Msg ("pull conflict " ^ msg))

    let find_contents store =
      let rec go store path acc =
        Store.list store path >>= fun steps ->
        Lwt_list.fold_left_s (fun acc (step, _) ->
            let full_path = path @ [ step ] in
            let str = String.concat "/" full_path in
            Store.kind store full_path >>= function
            | None ->
              Logs.warn (fun m -> m "no kind for %s" str);
              Lwt.return acc
            | Some `Contents -> Lwt.return (full_path :: acc)
            | Some `Node -> go store full_path acc) acc steps
      in
      go store [] [] >|= fun contents ->
      Logs.info (fun m -> m "%d contents" (List.length contents));
      contents

    let decode_digest filename str =
      let hex h s =
        match hex_of_string s with
        | Ok d -> Some (h, d)
        | Error `Msg msg ->
          Logs.warn (fun m -> m "%s invalid hex (%s) %s" filename msg s); None
      in
      match String.split_on_char '=' str with
      | [ data ] -> hex `MD5 data
      | [ "md5" ; data ] -> hex `MD5 data
      | [ "sha256" ; data ] -> hex `SHA256 data
      | [ "sha512" ; data ] -> hex `SHA512 data
      | [ hash ; _ ] -> Logs.warn (fun m -> m "%s unknown hash %s" filename hash); None
      | _ -> Logs.warn (fun m -> m "%s unexpected hash format %S" filename str); None

    let extract_urls filename str =
      (* in an opam file, there may be:
         url { src: <string> checksum: [ STRING ] } <- list of hash
         url { src: <string> checksum: STRING } <- single hash
         url { archive: <string> checksum: STRING } <- MD5
      *)
      let open OpamParserTypes.FullPos in
      let opamfile = OpamParser.FullPos.string str filename in
      let url_section =
        List.find_opt (function
            | { pelem = Section ({ section_kind = { pelem = "url" ; _ } ; _ }) ; _} -> true | _ -> false)
          opamfile.file_contents
      in
      match url_section with
      | Some { pelem = Section ({ section_items = { pelem = items ; _ }; _}) ; _ } ->
        begin
          let url =
            List.find_opt
              (function { pelem = Variable ({ pelem = "src" ; _ }, _); _ } -> true | _ -> false)
              items
          and archive =
            List.find_opt
              (function { pelem = Variable ({ pelem = "archive" ; _ }, _); _ } -> true | _ -> false)
              items
          and checksum =
            List.find_opt
              (function { pelem = Variable ({ pelem = "checksum" ; _ }, _); _ } -> true | _ -> false)
              items
          in
          let url =
            match url, archive with
            | Some { pelem = Variable (_, { pelem = String url ; _ }) }, None -> Some url
            | None, Some { pelem = Variable (_, { pelem = String url ; _ }) } -> Some url
            | _ ->
              Logs.warn (fun m -> m "%s neither src nor archive present" filename); None
          in
          let csum =
            match checksum with
            | Some { pelem = Variable (_, { pelem = List { pelem = csums ; _ } ; _ }); _ } ->
              let csums =
                List.fold_left (fun acc ->
                    function
                    | { pelem = String csum ; _ } ->
                      begin match decode_digest filename csum with
                        | None -> acc
                        | Some (h, v) ->
                          HM.update h (function
                              | None -> Some v
                              | Some v' when String.equal v v' -> None
                              | Some v' ->
                                Logs.warn (fun m -> m "for %s, hash %s, multiple keys are present: %s %s"
                                              (Option.value ~default:"NONE" url) (hash_to_string h) (hex_to_string v) (hex_to_string v'));
                                None)
                            acc
                      end
                    | _ -> acc) HM.empty csums
              in
              Some csums
            | Some { pelem = Variable (_, { pelem = String csum ; _ }) ; _ } ->
              begin match decode_digest filename csum with
                | None -> None
                | Some (h, v) -> Some (HM.singleton h v)
              end
            | _ ->
              Logs.warn (fun m -> m "couldn't decode checksum in %s" filename);
              None
          in
          match url, csum with
          | Some url, Some cs -> Some (url, cs)
          | _ -> None
        end
      | _ -> Logs.debug (fun m -> m "no url section for %s" filename); None

    let find_urls store =
      find_contents store >>= fun paths ->
      let opam_paths =
        List.filter (fun p -> match List.rev p with
            | "opam" :: _ -> true | _ -> false)
          paths
      in
      Lwt_list.fold_left_s (fun acc path ->
          Store.find store path >|= function
          | Some data ->
            (* TODO report parser errors *)
            (try
               let url_csums = extract_urls (String.concat "/" path) data in
               Option.fold ~none:acc ~some:(fun (url, csums) ->
                   if HM.cardinal csums = 0 then
                     (Logs.warn (fun m -> m "no checksums for %s, ignoring" url); acc)
                   else
                     SM.update url (function
                         | None -> Some csums
                         | Some csums' ->
                           if HM.for_all (fun h v ->
                               match HM.find_opt h csums with
                               | None -> true | Some v' -> String.equal v v')
                               csums'
                           then
                             Some (HM.union (fun _h v _v' -> Some v) csums csums')
                           else begin
                             Logs.warn (fun m -> m "mismatching hashes for %s: %s vs %s"
                                           url (hm_to_s csums') (hm_to_s csums));
                             None
                           end) acc) url_csums
             with _ ->
               Logs.warn (fun m -> m "some error in %s, ignoring" (String.concat "/" path));
               acc)
          | None -> acc)
        SM.empty opam_paths >|= fun urls ->
      Logs.info (fun m -> m "map contains %d urls" (SM.cardinal urls));
      urls
  end

  module Disk = struct
    type t = {
      mutable md5s : string SM.t ;
      mutable sha512s : string SM.t ;
      dev : KV.t ;
    }

    let empty dev = { md5s = SM.empty ; sha512s = SM.empty ; dev }

    (* on disk, we use a flat file system where the filename is the sha256 of the data *)
    (* on startup, we read + validate all data, and also store in the overlays (md5/sha512) the pointers *)
    (* the read can be md5/sha256/sha512 sum, and will output the data requested *)
    (* a write will compute the hashes and save the data (also validating potential other hashes) *)
    let init dev =
      KV.list dev Mirage_kv.Key.empty >>= function
      | Error e -> Logs.err (fun m -> m "error %a listing kv" KV.pp_error e); assert false
      | Ok entries ->
        let t = empty dev in
        Lwt_list.iter_s (fun (name, typ) ->
            match typ with
            | `Dictionary ->
              Logs.warn (fun m -> m "unexpected dictionary at %s" name);
              Lwt.return_unit
            | `Value ->
              KV.get dev (Mirage_kv.Key.v name) >>= function
              | Ok data ->
                let cs = Cstruct.of_string data in
                let digest = Mirage_crypto.Hash.digest `SHA256 cs in
                if Cstruct.equal digest (Cstruct.of_string name) then
                  let md5 = Mirage_crypto.Hash.digest `MD5 cs
                  and sha512 = Mirage_crypto.Hash.digest `SHA512 cs
                  in
                  let md5s = SM.add (Cstruct.to_string md5) name t.md5s
                  and sha512s = SM.add (Cstruct.to_string sha512) name t.sha512s
                  in
                  t.md5s <- md5s ; t.sha512s <- sha512s;
                  Lwt.return_unit
                else begin
                  Logs.err (fun m -> m "corrupt data, expected %s, read %s"
                               (hex_to_string name)
                               (hex_to_string (Cstruct.to_string digest)));
                  KV.remove dev (Mirage_kv.Key.v name) >|= function
                  | Ok () -> ()
                  | Error e ->
                    Logs.err (fun m -> m "error %a while removing %s"
                                 KV.pp_write_error e (hex_to_string name))
                end
              | Error e ->
                Logs.err (fun m -> m "error %a reading %s"
                             KV.pp_error e (hex_to_string name));
                Lwt.return_unit)
          entries >|= fun () ->
        t

    let write t data hm =
      let cs = Cstruct.of_string data in
      let sha256 = Mirage_crypto.Hash.digest `SHA256 cs |> Cstruct.to_string
      and md5 = Mirage_crypto.Hash.digest `MD5 cs |> Cstruct.to_string
      and sha512 = Mirage_crypto.Hash.digest `SHA512 cs |> Cstruct.to_string
      in
      if
        HM.for_all (fun h v ->
            let v' =
              match h with `MD5 -> md5 | `SHA256 -> sha256 | `SHA512 -> sha512 | _ -> assert false
            in
            if String.equal v v' then
              true
            else begin
              Logs.err (fun m -> m "hash mismatch %s: expected %s, got %s"
                           (hash_to_string h) (hex_to_string v) (hex_to_string v'));
              false
            end) hm
      then
        KV.set t.dev (Mirage_kv.Key.v sha256) data >|= function
        | Ok () ->
          t.md5s <- SM.add md5 sha256 t.md5s;
          t.sha512s <- SM.add sha512 sha256 t.sha512s;
          Logs.info (fun m -> m "wrote %s (%d bytes)" (hex_to_string sha256)
                        (String.length data))
        | Error e ->
          Logs.err (fun m -> m "error %a while writing %s"
                       KV.pp_write_error e (hex_to_string sha256))
      else
        Lwt.return_unit

    let find_key t h v =
      match hex_of_string v with
      | Error `Msg msg ->
        Logs.err (fun m -> m "error %s while decoding hex %s" msg v);
        Error `Bad_request
      | Ok bin ->
        match
          match h with
          | `MD5 -> SM.find_opt bin t.md5s
          | `SHA512 -> SM.find_opt bin t.sha512s
          | `SHA256 -> Some bin
          | _ -> None
        with
        | None ->
          Logs.err (fun m -> m "couldn't find %s" v);
          Error `Not_found
        | Some x -> Ok x

    let exists t h v =
      match find_key t h v with
      | Error _ -> Lwt.return false
      | Ok x ->
        KV.exists t.dev (Mirage_kv.Key.v x) >|= function
        | Ok Some `Value -> true
        | Ok Some `Dictionary ->
          Logs.err (fun m -> m "unexpected dictionary for %s %s"
                       (hash_to_string h) (hex_to_string v));
          false
        | Ok None -> false
        | Error e ->
          Logs.err (fun m -> m "exists %s %s returned %a"
                       (hash_to_string h) (hex_to_string v)
                       KV.pp_error e);
          false

    let read t h v =
      match find_key t h v with
      | Error _ as e -> Lwt.return e
      | Ok x ->
        KV.get t.dev (Mirage_kv.Key.v x) >|= function
        | Ok data -> Ok data
        | Error e ->
          Logs.err (fun m -> m "error %a while reading %s %s"
                       KV.pp_error e (hash_to_string h) v);
          Error `Not_found
  end

  let resolve_location ~uri ~location =
    match String.split_on_char '/' location with
    | "http:" :: "" :: _ -> Ok location
    | "https:" :: "" :: _ -> Ok location
    | "" :: "" :: _ ->
      let schema = String.sub uri 0 (String.index uri '/') in
      Ok (schema ^ location)
    | "" :: _ ->
      (match String.split_on_char '/' uri with
       | schema :: "" :: user_pass_host_port :: _ ->
         Ok (String.concat "/" [schema ; "" ; user_pass_host_port ^ location])
       | _ -> Error (`Msg ("expected an absolute uri, got: " ^ uri)))
    | _ -> Error (`Msg ("unknown location (relative path): " ^ location))

  let start kv _time _pclock stack dns _paf_cohttp git_ctx =
    Git.connect git_ctx >>= fun (store, upstream) ->
    Git.pull store upstream >>= function
    | Error `Msg msg -> Lwt.fail_with msg
    | Ok msg ->
      Logs.info (fun m -> m "git: %s" msg);
      Git.find_urls store >>= fun urls ->
      Disk.init kv >>= fun disk ->
      let ctx =
        Mimic.empty
        |> with_sleep
        |> with_tcp         (* stack -> ipaddr -> port => (stack * ipaddr * port) *)
        |> with_tls         (* domain_name -> tls -> stack -> ipaddr -> port => (domain_name * tls * stack * ipaddr * port) *)
        |> with_resolv      (* domain_name => ipaddr *)
        |> with_stack stack (* stack *)
        |> with_dns dns     (* dns *) in
      let rec follow count uri =
        if count = 0 then begin
          Logs.err (fun m -> m "redirection limit exceeded");
          Lwt.return None
        end else begin
          Logs.info (fun m -> m "retrieving %s" uri);
          Client.get ~ctx (Uri.of_string uri) >>= fun (resp, body) ->
          match resp.Cohttp.Response.status with
          | `OK ->
            Cohttp_lwt.Body.to_string body >|= fun str ->
            Some str
          | #Cohttp.Code.redirection_status ->
            begin match Cohttp.Header.get resp.Cohttp.Response.headers "location" with
              | Some location ->
                begin match resolve_location ~uri ~location with
                  | Error `Msg msg ->
                    Logs.err (fun m -> m "error %s resolving redirect location %s"
                                 msg location);
                    Lwt.return None
                  | Ok new_uri -> follow (pred count) new_uri
                end
              | None ->
                Logs.err (fun m -> m "redirect without location");
                Lwt.return None
            end
          | s ->
            Logs.err (fun m -> m "error %s while fetching %s"
                         (Cohttp.Code.string_of_status resp.Cohttp.Response.status)
                         uri);
            Lwt.return None
        end
      in
      Lwt_list.iter_p (fun (url, csums) ->
          HM.fold (fun h v r ->
              r >>= function
              | true -> Disk.exists disk h v
              | false -> Lwt.return false)
            csums (Lwt.return true) >>= function
          | true ->
            Logs.info (fun m -> m "ignoring %s (already present)" url);
            Lwt.return_unit
          | false ->
            follow 20 url >>= function
            | Some str -> Disk.write disk str csums
            | None -> Lwt.return_unit)
        (SM.bindings urls) >|= fun () ->
      Logs.info (fun m -> m "done")
end
