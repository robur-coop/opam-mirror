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
  (_ : sig end)
  (HTTP : Http_mirage_client.S) = struct

  module Store = Irmin_mirage_git.Mem.KV.Make(Irmin.Contents.String)
  module Sync = Irmin.Sync.Make(Store)

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

  let hash_of_string = function
    | "md5" -> Ok `MD5
    | "sha256" -> Ok `SHA256
    | "sha512" -> Ok `SHA512
    | h -> Error (`Msg ("unknown hash algorithm: " ^ h))

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
      | Ok (`Head c as s) -> Ok (c, Fmt.str "pulled %a" Sync.pp_status s)
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
      go store [] []

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
            | Some { pelem = Variable (_, { pelem = String url ; _ }) ; _ }, None -> Some url
            | None, Some { pelem = Variable (_, { pelem = String url ; _ }); _ } -> Some url
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
        SM.empty opam_paths
  end

  module Disk = struct
    type t = {
      mutable md5s : string SM.t ;
      mutable sha512s : string SM.t ;
      key_hex : bool ;
      dev : KV.t ;
    }

    let empty key_hex dev = { md5s = SM.empty ; sha512s = SM.empty ; key_hex ; dev }

    let key t d =
      let d = Cstruct.to_string d in
      if t.key_hex then hex_to_string d else d

    let key_to_string t d = if t.key_hex then d else hex_to_string d

    let key_of_string t v =
      if t.key_hex then
        Ok v
      else
        match hex_of_string v with
        | Error `Msg msg ->
          Logs.err (fun m -> m "error %s while decoding hex %s" msg v);
          Error `Bad_request
        | Ok bin -> Ok bin

    (* on disk, we use a flat file system where the filename is the sha256 of the data *)
    (* on startup, we read + validate all data, and also store in the overlays (md5/sha512) the pointers *)
    (* the read can be md5/sha256/sha512 sum, and will output the data requested *)
    (* a write will compute the hashes and save the data (also validating potential other hashes) *)
    let init ?(key_hex = false) dev =
      KV.list dev Mirage_kv.Key.empty >>= function
      | Error e -> Logs.err (fun m -> m "error %a listing kv" KV.pp_error e); assert false
      | Ok entries ->
        let t = empty key_hex dev in
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
                if String.equal name (key t digest) then begin
                  let md5 = Mirage_crypto.Hash.digest `MD5 cs |> key t
                  and sha512 = Mirage_crypto.Hash.digest `SHA512 cs |> key t
                  in
                  let md5s = SM.add md5 name t.md5s
                  and sha512s = SM.add sha512 name t.sha512s
                  in
                  t.md5s <- md5s ; t.sha512s <- sha512s;
                  Logs.debug (fun m -> m "added %s" (key_to_string t name));
                  Lwt.return_unit
                end else begin
                  Logs.err (fun m -> m "corrupt data, expected %s, read %s"
                               (key_to_string t name)
                               (hex_to_string (Cstruct.to_string digest)));
                  KV.remove dev (Mirage_kv.Key.v name) >|= function
                  | Ok () -> ()
                  | Error e ->
                    Logs.err (fun m -> m "error %a while removing %s"
                                 KV.pp_write_error e (key_to_string t name))
                end
              | Error e ->
                Logs.err (fun m -> m "error %a reading %s"
                             KV.pp_error e (key_to_string t name));
                Lwt.return_unit)
          entries >|= fun () ->
        t

    let write t ~url data hm =
      let cs = Cstruct.of_string data in
      let sha256 = Mirage_crypto.Hash.digest `SHA256 cs |> key t
      and md5 = Mirage_crypto.Hash.digest `MD5 cs |> key t
      and sha512 = Mirage_crypto.Hash.digest `SHA512 cs |> key t
      in
      if
        HM.for_all (fun h v ->
            let v' =
              match h with `MD5 -> md5 | `SHA256 -> sha256 | `SHA512 -> sha512 | _ -> assert false
            in
            let v = if t.key_hex then hex_to_string v else v in
            if String.equal v v' then
              true
            else begin
              Logs.err (fun m -> m "%s hash mismatch %s: expected %s, got %s" url
                           (hash_to_string h) (key_to_string t v) (key_to_string t v'));
              false
            end) hm
      then begin
        KV.set t.dev (Mirage_kv.Key.v sha256) data >|= function
        | Ok () ->
          t.md5s <- SM.add md5 sha256 t.md5s;
          t.sha512s <- SM.add sha512 sha256 t.sha512s;
          Logs.debug (fun m -> m "wrote %s (%d bytes)" (key_to_string t sha256)
                        (String.length data))
        | Error e ->
          Logs.err (fun m -> m "error %a while writing %s (key %s)"
                       KV.pp_write_error e url (key_to_string t sha256))
      end else
        Lwt.return_unit

    let find_key t h v =
      let ( let* ) = Result.bind in
      let* key = key_of_string t v in
      match
        match h with
        | `MD5 -> SM.find_opt key t.md5s
        | `SHA512 -> SM.find_opt key t.sha512s
        | `SHA256 -> Some key
        | _ -> None
      with
      | None -> Error `Not_found
      | Some x -> Ok x

    let exists t h v =
      match find_key t h v with
      | Error _ -> Lwt.return false
      | Ok x ->
        KV.exists t.dev (Mirage_kv.Key.v x) >|= function
        | Ok Some `Value -> true
        | Ok Some `Dictionary ->
          Logs.err (fun m -> m "unexpected dictionary for %s %s"
                       (hash_to_string h) (key_to_string t v));
          false
        | Ok None -> false
        | Error e ->
          Logs.err (fun m -> m "exists %s %s returned %a"
                       (hash_to_string h) (key_to_string t v)
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

    let last_modified t h v =
      match find_key t h v with
      | Error _ as e -> Lwt.return e
      | Ok x ->
        KV.last_modified t.dev (Mirage_kv.Key.v x) >|= function
        | Ok data -> Ok data
        | Error e ->
          Logs.err (fun m -> m "error %a while reading %s %s"
                       KV.pp_error e (hash_to_string h) v);
          Error `Not_found
  end

  module Tarball = struct
    module Async = struct
      type 'a t = 'a
      let ( >>= ) x f = f x
      let return x = x
    end

    module Writer = struct
      type out_channel = Buffer.t
      type 'a t = 'a
      let really_write buf data =
        Buffer.add_string buf (Cstruct.to_string data)
    end

    (* That's not very interesting here, we just ignore everything*)
    module Reader = struct
      type in_channel = unit
      type 'a t = 'a
      let really_read _in _data = ()
      let skip _in _len = ()
      let read _in _data = 0
    end

    module Tar_Gz = Tar_gz.Make (Async)(Writer)(Reader)

    let of_git repo store =
      let out_channel = Buffer.create 1024 in
      let now = Ptime.v (Pclock.now_d_ps ()) in
      let mtime = Option.value ~default:0 Ptime.(Span.to_int_s (to_span now)) in
      let gz_out =
        Tar_Gz.of_out_channel ~level:4 ~mtime:(Int32.of_int mtime)
          Gz.Unix out_channel
      in
      Git.find_contents store >>= fun paths ->
      Lwt_list.iter_s (fun path ->
          Store.find store path >|= function
          | Some data ->
            let data =
              if path = [ "repo" ] then repo else data
            in
            let file_mode = 0o644 (* would be great to retrieve the actual one - but not needed (since opam-repository doesn't use it anyways)! *)
            and mod_time = Int64.of_int mtime
            and user_id = 0
            and group_id = 0
            and size = String.length data
            in
            let hdr =
              Tar.Header.make ~file_mode ~mod_time ~user_id ~group_id
                (String.concat "/" path) (Int64.of_int size)
            in
            let o = ref false in
            let stream () = if !o then None else (o := true; Some data) in
            Tar_Gz.write_block ~level:Tar.Header.Ustar hdr gz_out stream
          | None -> ())
        paths >|= fun () ->
      Tar_Gz.write_end gz_out;
      Buffer.contents out_channel
  end

  module Serve = struct
    let ptime_to_http_date ptime =
      let (y, m, d), ((hh, mm, ss), _) = Ptime.to_date_time ptime
      and weekday = match Ptime.weekday ptime with
        | `Mon -> "Mon" | `Tue -> "Tue" | `Wed -> "Wed" | `Thu -> "Thu"
        | `Fri -> "Fri" | `Sat -> "Sat" | `Sun -> "Sun"
      and month =
        [| "Jan" ; "Feb" ; "Mar" ; "Apr" ; "May" ; "Jun" ;
           "Jul" ; "Aug" ; "Sep" ; "Oct" ; "Nov" ; "Dec" |]
    in
    let m' = Array.get month (pred m) in
    Printf.sprintf "%s, %02d %s %04d %02d:%02d:%02d GMT" weekday d m' y hh mm ss

    let commit_id commit =
      Fmt.to_to_string (Irmin.Type.pp Store.Hash.t) (Store.Commit.hash commit)

    let repo commit =
      let upstream = List.hd (String.split_on_char '#' (Key_gen.remote ()))
      and commit = commit_id commit
      in
      Fmt.str
        {|opam-version: "2.0"
upstream: "%s#%s"
archive-mirrors: "cache"
stamp: %S
|} upstream commit commit

    let modified commit =
      let info = Store.Commit.info commit in
      let ptime =
        Option.value ~default:(Ptime.v (Pclock.now_d_ps ()))
          (Ptime.of_float_s (Int64.to_float (Store.Info.date info)))
      in
      ptime_to_http_date ptime

    type t = {
      commit_id : string ;
      modified : string ;
      repo : string ;
      index : string ;
    }

    let create commit repo index =
      let commit_id = commit_id commit
      and modified = modified commit
      in
      { commit_id ; modified ; repo ; index }

    let not_modified request (modified, etag) =
      match Httpaf.Headers.get request.Httpaf.Request.headers "if-modified-since" with
      | Some ts -> String.equal ts modified
      | None -> match Httpaf.Headers.get request.Httpaf.Request.headers "if-none-match" with
        | Some etags -> List.mem etag (String.split_on_char ',' etags)
        | None -> false

    let not_found reqd path =
      let data = "Resource not found " ^ path in
      let headers = Httpaf.Headers.of_list
          [ "content-length", string_of_int (String.length data) ] in
      let resp = Httpaf.Response.create ~headers `Not_found in
      Httpaf.Reqd.respond_with_string reqd resp data

    let respond_with_empty reqd resp =
      let hdr =
        Httpaf.Headers.add_unless_exists resp.Httpaf.Response.headers
          "connection" "close"
      in
      let resp = { resp with Httpaf.Response.headers = hdr } in
      Httpaf.Reqd.respond_with_string reqd resp ""

    (* From the OPAM manual, all we need:
       /repo -- repository configuration file
       /cache -- cached archives
       /index.tar.gz -- archive containing the whole repository contents
    *)
    (* may include "announce: [ string { filter } ... ]" *)
    (* use Key_gen.remote for browse & upstream *)

    (* for repo and index.tar.gz:
        if Last_modified.not_modified request then
          let resp = Httpaf.Response.create `Not_modified in
          respond_with_empty reqd resp
        else *)
    let dispatch t store _flow _conn reqd =
      let request = Httpaf.Reqd.request reqd in
      Logs.info (fun f -> f "requested %s" request.Httpaf.Request.target);
      match String.split_on_char '/' request.Httpaf.Request.target with
      | [ ""; "repo" ] ->
        if not_modified request (t.modified, t.commit_id) then
          let resp = Httpaf.Response.create `Not_modified in
          respond_with_empty reqd resp
        else
          let data = t.repo in
          let mime_type = "text/plain" in
          let headers = [
            "content-type", mime_type ;
            "etag", t.commit_id ;
            "last-modified", t.modified ;
            "content-length", string_of_int (String.length data) ;
          ] in
          let headers = Httpaf.Headers.of_list headers in
          let resp = Httpaf.Response.create ~headers `OK in
          Httpaf.Reqd.respond_with_string reqd resp data
      | [ ""; "index.tar.gz" ] ->
        (* deliver prepared tarball *)
        if not_modified request (t.modified, t.commit_id) then
          let resp = Httpaf.Response.create `Not_modified in
          respond_with_empty reqd resp
        else
          let data = t.index in
          let mime_type = "application/octet-stream" in
          let headers = [
            "content-type", mime_type ;
            "etag", t.commit_id ;
            "last-modified", t.modified ;
            "content-length", string_of_int (String.length data) ;
          ] in
          let headers = Httpaf.Headers.of_list headers in
          let resp = Httpaf.Response.create ~headers `OK in
          Httpaf.Reqd.respond_with_string reqd resp data
      | "" :: "cache" :: hash_algo :: _ :: hash :: [] ->
        (* `<hash-algo>/<first-2-hash-characters>/<hash>` *)
        begin
          match hash_of_string hash_algo with
          | Error `Msg msg ->
            Logs.warn (fun m -> m "error decoding hash algo: %s" msg);
            not_found reqd request.Httpaf.Request.target
          | Ok h ->
            Lwt.async (fun () ->
                (Disk.last_modified store h hash >|= function
                  | Error _ ->
                    Logs.warn (fun m -> m "error retrieving last modified");
                    t.modified
                  | Ok v -> ptime_to_http_date (Ptime.v v)) >>= fun last_modified ->
                if not_modified request (last_modified, hash) then
                  let resp = Httpaf.Response.create `Not_modified in
                  respond_with_empty reqd resp;
                  Lwt.return_unit
                else
                  Disk.read store h hash >>= function
                  | Error _ ->
                    not_found reqd request.Httpaf.Request.target;
                    Lwt.return_unit
                  | Ok data ->
                    let mime_type = "application/octet-stream" in
                    let headers = [
                      "content-type", mime_type ;
                      "etag", hash ;
                      "last-modified", last_modified ;
                      "content-length", string_of_int (String.length data) ;
                    ] in
                    let headers = Httpaf.Headers.of_list headers in
                    let resp = Httpaf.Response.create ~headers `OK in
                    Httpaf.Reqd.respond_with_string reqd resp data ;
                    Lwt.return_unit)
        end
      | _ ->
        Logs.warn (fun m -> m "unknown request %s" request.Httpaf.Request.target);
        not_found reqd request.Httpaf.Request.target

  end

  let download_archives disk http_ctx store =
    Git.find_urls store >>= fun urls ->
    let pool = Lwt_pool.create 20 (Fun.const Lwt.return_unit) in
    Lwt_list.iter_p (fun (url, csums) ->
        Lwt_pool.use pool @@ fun () ->
        HM.fold (fun h v r ->
            r >>= function
            | true -> Disk.exists disk h (hex_to_string v)
            | false -> Lwt.return false)
          csums (Lwt.return true) >>= function
        | true ->
          Logs.debug (fun m -> m "ignoring %s (already present)" url);
          Lwt.return_unit
        | false ->
          Logs.debug (fun m -> m "downloading %s" url);
          Http_mirage_client.one_request
            ~alpn_protocol:HTTP.alpn_protocol
            ~authenticator:HTTP.authenticator
            ~ctx:http_ctx url >>= function
          | Ok (resp, Some str) ->
            if resp.status = `OK then begin
              Logs.info (fun m -> m "downloaded %s" url);
              Disk.write disk ~url str csums
            end else begin
              Logs.warn (fun m -> m "%s: %a (reason %s)"
                            url H2.Status.pp_hum resp.status resp.reason);
              Lwt.return_unit
            end
          | _ -> Lwt.return_unit)
      (SM.bindings urls) >|= fun () ->
    Logs.info (fun m -> m "downloading of %d urls done" (SM.cardinal urls))

  module Paf = Paf_mirage.Make(Time)(Stack.TCP)

  let start kv _time _pclock stack git_ctx http_ctx =
    let key_hex = Key_gen.key_hex () in
    Disk.init ~key_hex kv >>= fun disk ->
    if Key_gen.check () then Lwt.return_unit
    else
      Git.connect git_ctx >>= fun (store, upstream) ->
      Git.pull store upstream >>= function
      | Error `Msg msg -> Lwt.fail_with msg
      | Ok (commit, msg) ->
        Logs.info (fun m -> m "git: %s" msg);
        let repo = Serve.repo commit in
        Tarball.of_git repo store >>= fun index ->
        let serve = Serve.create commit repo index in
        Paf.init ~port:(Key_gen.port ()) (Stack.tcp stack) >>= fun t ->
        let service =
          Paf.http_service
            ~error_handler:(fun _ ?request:_ _ _ -> ())
            (Serve.dispatch serve disk)
        in
        let `Initialized th = Paf.serve service t in
        Logs.info (fun f -> f "listening on %d/HTTP" (Key_gen.port ()));
        download_archives disk http_ctx store >>= fun () ->
        (th >|= fun _v -> ())
end
