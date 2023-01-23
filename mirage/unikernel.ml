open Lwt.Infix

let argument_error = 64

module Make
  (BLOCK : Mirage_block.S)
  (Time : Mirage_time.S)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Tcpip.Stack.V4V6)
  (_ : sig end)
  (HTTP : Http_mirage_client.S) = struct

  module Part = Mirage_block_partition.Make(BLOCK)
  module KV = Tar_mirage.Make_KV_RW(Pclock)(Part)
  module Cache = OneFFS.Make(Part)
  module Store = Git_kv.Make(Pclock)

  module SM = Map.Make(String)
  module SSet = Set.Make(String)

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

  let hex_to_key h = Mirage_kv.Key.v (hex_to_string h)

  let hex_of_string s =
    match Hex.to_string (`Hex s) with
    | d -> Ok d
    | exception Invalid_argument err -> Error (`Msg err)

  let hm_to_s hm =
    HM.fold (fun h v acc ->
        hash_to_string h ^ "=" ^ hex_to_string v ^ "\n" ^ acc)
      hm ""

  module Git = struct
    let find_contents store =
      let rec go store path acc =
        Store.list store path >>= function
        | Error e ->
          Logs.err (fun m -> m "error %a while listing %a"
                       Store.pp_error e Mirage_kv.Key.pp path);
          Lwt.return acc
        | Ok steps ->
          Lwt_list.fold_left_s (fun acc (step, _) ->
              Store.exists store step >>= function
              | Error e ->
                Logs.err (fun m -> m "error %a for exists %a" Store.pp_error e
                             Mirage_kv.Key.pp step);
                Lwt.return acc
              | Ok None ->
                Logs.warn (fun m -> m "no typ for %a" Mirage_kv.Key.pp step);
                Lwt.return acc
              | Ok Some `Value -> Lwt.return (step :: acc)
              | Ok Some `Dictionary -> go store step acc) acc steps
      in
      go store Mirage_kv.Key.empty []

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
        List.filter (fun p -> Mirage_kv.Key.basename p = "opam") paths
      in
      Lwt_list.fold_left_s (fun acc path ->
          Store.get store path >|= function
          | Ok data ->
            (* TODO report parser errors *)
            (try
               let url_csums = extract_urls (Mirage_kv.Key.to_string path) data in
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
               Logs.warn (fun m -> m "some error in %a, ignoring" Mirage_kv.Key.pp path);
               acc)
          | Error e -> Logs.warn (fun m -> m "Store.get: %a" Store.pp_error e); acc)
        SM.empty opam_paths
  end

  module Disk = struct
    type t = {
      mutable md5s : string SM.t ;
      mutable sha512s : string SM.t ;
      dev : KV.t ;
      dev_md5s : Cache.t ;
      dev_sha512s : Cache.t ;
    }

    let empty dev dev_md5s dev_sha512s = { md5s = SM.empty ; sha512s = SM.empty ; dev; dev_md5s; dev_sha512s }

    let to_hex d =
      let d = Cstruct.to_string d in
      hex_to_string d

    let marshal_sm (sm : string SM.t) =
      let version = char_of_int 1 in
      String.make 1 version ^ Marshal.to_string sm []

    let unmarshal_sm s =
      let version = int_of_char s.[0] in
      match version with
      | 1 -> Ok (Marshal.from_string s 1 : string SM.t)
      | _ -> Error ("Unsupported version " ^ string_of_int version)

    let update_caches t =
      Cache.write t.dev_md5s (marshal_sm t.md5s) >>= fun r ->
      (match r with
       | Ok () -> Logs.info (fun m -> m "Set 'md5s'")
       | Error e -> Logs.warn (fun m -> m "Failed to write 'md5s': %a" Cache.pp_write_error e));
      Cache.write t.dev_sha512s (marshal_sm t.sha512s) >>= fun r ->
      match r with
      | Ok () -> Logs.info (fun m -> m "Set 'sha512s'"); Lwt.return_unit
      | Error e ->
        Logs.warn (fun m -> m "Failed to write 'sha512s': %a" Cache.pp_write_error e);
        Lwt.return_unit

    let find_key t h key =
      match
        match h with
        | `MD5 ->
          Option.map Mirage_kv.Key.v (SM.find_opt (Mirage_kv.Key.basename key) t.md5s)
        | `SHA512 ->
          Option.map Mirage_kv.Key.v (SM.find_opt (Mirage_kv.Key.basename key) t.sha512s)
        | `SHA256 -> Some key
        | _ -> None
      with
      | None -> Error `Not_found
      | Some x -> Ok x

    let read_chunked t h v f a =
      match find_key t h v with
      | Error `Not_found ->
        Lwt.return (Error (`Not_found v))
      | Ok key ->
        KV.size t.dev key >>= function
        | Error e ->
          Logs.err (fun m -> m "error %a while reading %s %a"
                       KV.pp_error e (hash_to_string h) Mirage_kv.Key.pp v);
          Lwt.return (Error (`Not_found key))
        | Ok len ->
          let chunk_size = 4096 in
          let rec read_more a offset =
            if offset < len then
              KV.get_partial t.dev key ~offset ~length:chunk_size >>= function
              | Ok data ->
                f a data >>= fun a ->
                read_more a Optint.Int63.(add offset (of_int chunk_size))
              | Error e ->
                Logs.err (fun m -> m "error %a while reading %s %a"
                             KV.pp_error e (hash_to_string h) Mirage_kv.Key.pp v);
                Lwt.return (Error e)
            else
              Lwt.return (Ok a)
          in
          read_more a Optint.Int63.zero

    (* on disk, we use a flat file system where the filename is the sha256 of the data *)
    let init ~verify_sha256 dev dev_md5s dev_sha512s =
      KV.list dev Mirage_kv.Key.empty >>= function
      | Error e -> Logs.err (fun m -> m "error %a listing kv" KV.pp_error e); assert false
      | Ok entries ->
        let t = empty dev dev_md5s dev_sha512s in
        Cache.read t.dev_md5s >>= fun r ->
        (match r with
         | Ok Some s ->
           if not verify_sha256 then
             Result.iter (fun md5s -> t.md5s <- md5s) (unmarshal_sm s)
         | Ok None -> Logs.debug (fun m -> m "No md5s cached")
         | Error e -> Logs.warn (fun m -> m "Error reading md5s cache: %a" Cache.pp_error e));
        Cache.read t.dev_sha512s >>= fun r ->
        (match r with
         | Ok Some s ->
           if not verify_sha256 then
             Result.iter (fun sha512s -> t.sha512s <- sha512s) (unmarshal_sm s)
         | Ok None -> Logs.debug (fun m -> m "No sha512s cached")
         | Error e -> Logs.warn (fun m -> m "Error reading sha512s cache: %a" Cache.pp_error e));
        let md5s = SSet.of_list (List.map snd (SM.bindings t.md5s))
        and sha512s = SSet.of_list (List.map snd (SM.bindings t.sha512s)) in
        let idx = ref 1 in
        Lwt_list.iter_s (fun (path, typ) ->
            if !idx mod 10 = 0 then Gc.full_major () ;
            match typ with
            | `Dictionary ->
              Logs.warn (fun m -> m "unexpected dictionary at %a" Mirage_kv.Key.pp path);
              Lwt.return_unit
            | `Value ->
              let open Mirage_crypto.Hash in
              let sha256_final =
                if verify_sha256 then
                  let f s =
                    let digest = SHA256.get s in
                    if not (String.equal (Mirage_kv.Key.basename path) (to_hex digest)) then
                      Logs.err (fun m -> m "corrupt SHA256 data for %a, \
                                            computed %s (should remove)"
                                   Mirage_kv.Key.pp path (to_hex digest))
                  in
                  Some f
                else
                  None
              and md5_final =
                if not (SSet.mem (Mirage_kv.Key.basename path) md5s) then
                  let f s =
                    let digest = MD5.get s in
                    t.md5s <- SM.add (to_hex digest) (Mirage_kv.Key.basename path) t.md5s
                  in
                  Some f
                else
                  None
              and sha512_final =
                if not (SSet.mem (Mirage_kv.Key.basename path) sha512s) then
                  let f s =
                    let digest = SHA512.get s in
                    t.sha512s <- SM.add (to_hex digest) (Mirage_kv.Key.basename path) t.sha512s
                  in
                  Some f
                else
                  None
              in
              match sha256_final, md5_final, sha512_final with
              | None, None, None -> Lwt.return_unit
              | _ ->
                read_chunked t `SHA256 path
                  (fun (sha256, md5, sha512) data ->
                     let cs = Cstruct.of_string data in
                     Lwt.return
                       (Option.map (fun t -> SHA256.feed t cs) sha256,
                        Option.map (fun t -> MD5.feed t cs) md5,
                        Option.map (fun t -> SHA512.feed t cs) sha512))
                  (Option.map (fun _ -> SHA256.empty) sha256_final,
                   Option.map (fun _ -> MD5.empty) md5_final,
                   Option.map (fun _ -> SHA512.empty) sha512_final) >|= function
                | Error e ->
                  Logs.err (fun m -> m "error %a of %a while computing digests"
                               KV.pp_error e Mirage_kv.Key.pp path)
                | Ok (sha256, md5, sha512) ->
                  Option.iter (fun f -> f (Option.get sha256)) sha256_final;
                  Option.iter (fun f -> f (Option.get md5)) md5_final;
                  Option.iter (fun f -> f (Option.get sha512)) sha512_final;
                  Logs.info (fun m -> m "added %a" Mirage_kv.Key.pp path))
          entries >>= fun () ->
        update_caches t >|= fun () ->
        t

    let write t ~url data hm =
      let cs = Cstruct.of_string data in
      let sha256 = Mirage_crypto.Hash.digest `SHA256 cs |> to_hex
      and md5 = Mirage_crypto.Hash.digest `MD5 cs |> to_hex
      and sha512 = Mirage_crypto.Hash.digest `SHA512 cs |> to_hex
      in
      if
        HM.for_all (fun h v ->
            let v' =
              match h with `MD5 -> md5 | `SHA256 -> sha256 | `SHA512 -> sha512 | _ -> assert false
            in
            let v = hex_to_string v in
            if String.equal v v' then
              true
            else begin
              Logs.err (fun m -> m "%s hash mismatch %s: expected %s, got %s" url
                           (hash_to_string h) v v');
              false
            end) hm
      then begin
        KV.set t.dev (Mirage_kv.Key.v sha256) data >|= function
        | Ok () ->
          t.md5s <- SM.add md5 sha256 t.md5s;
          t.sha512s <- SM.add sha512 sha256 t.sha512s;
          Logs.debug (fun m -> m "wrote %s (%d bytes)" sha256
                         (String.length data))
        | Error e ->
          Logs.err (fun m -> m "error %a while writing %s (key %s)"
                       KV.pp_write_error e url sha256)
      end else
        Lwt.return_unit

    let exists t h v =
      match find_key t h v with
      | Error _ -> Lwt.return false
      | Ok x ->
        KV.exists t.dev x >|= function
        | Ok Some `Value -> true
        | Ok Some `Dictionary ->
          Logs.err (fun m -> m "unexpected dictionary for %s %a"
                       (hash_to_string h) Mirage_kv.Key.pp v);
          false
        | Ok None -> false
        | Error e ->
          Logs.err (fun m -> m "exists %s %a returned %a"
                       (hash_to_string h) Mirage_kv.Key.pp v KV.pp_error e);
          false

    let last_modified t h v =
      match find_key t h v with
      | Error _ as e -> Lwt.return e
      | Ok x ->
        KV.last_modified t.dev x >|= function
        | Ok data -> Ok data
        | Error e ->
          Logs.err (fun m -> m "error %a while last_modified %s %a"
                       KV.pp_error e (hash_to_string h) Mirage_kv.Key.pp v);
          Error `Not_found

    let size t h v =
      match find_key t h v with
      | Error _ as e -> Lwt.return e
      | Ok x ->
        KV.size t.dev x >|= function
        | Ok s -> Ok s
        | Error e ->
          Logs.err (fun m -> m "error %a while size %s %a"
                       KV.pp_error e (hash_to_string h) Mirage_kv.Key.pp v);
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
          Store.get store path >|= function
          | Ok data ->
            let data =
              if Mirage_kv.Key.(equal path (v "repo")) then repo else data
            in
            let file_mode = 0o644 (* would be great to retrieve the actual one - but not needed (since opam-repository doesn't use it anyways)! *)
            and mod_time = Int64.of_int mtime
            and user_id = 0
            and group_id = 0
            and size = String.length data
            in
            let hdr =
              Tar.Header.make ~file_mode ~mod_time ~user_id ~group_id
                (Mirage_kv.Key.to_string path) (Int64.of_int size)
            in
            let o = ref false in
            let stream () = if !o then None else (o := true; Some data) in
            Tar_Gz.write_block ~level:Tar.Header.Ustar hdr gz_out stream
          | Error e -> Logs.warn (fun m -> m "Store error: %a" Store.pp_error e))
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

    let commit_id git_kv =
      Store.digest git_kv Mirage_kv.Key.empty >|= fun r ->
      Result.get_ok r

    let repo commit =
      let upstream = List.hd (String.split_on_char '#' (Key_gen.remote ())) in
      Fmt.str
        {|opam-version: "2.0"
upstream: "%s#%s"
archive-mirrors: "cache"
stamp: %S
|} upstream commit commit

    let modified git_kv =
      Store.last_modified git_kv Mirage_kv.Key.empty >|= fun r ->
      let v =
        Result.fold r
          ~ok:Fun.id
          ~error:(fun _ -> Ptime.v (Pclock.now_d_ps ()))
      in
      ptime_to_http_date v

    type t = {
      mutable commit_id : string ;
      mutable modified : string ;
      mutable repo : string ;
      mutable index : string ;
    }

    let create git_kv =
      commit_id git_kv >>= fun commit_id ->
      modified git_kv >>= fun modified ->
      let repo = repo commit_id in
      Tarball.of_git repo git_kv >|= fun index ->
      { commit_id ; modified ; repo ; index }

    let update_lock = Lwt_mutex.create ()

    let update_git t git_kv =
      Lwt_mutex.with_lock update_lock (fun () ->
          Logs.info (fun m -> m "pulling the git repository");
          Git_kv.pull git_kv >>= function
          | Error `Msg msg ->
            Logs.err (fun m -> m "error %s while updating git" msg);
            Lwt.return None
          | Ok [] ->
            Logs.info (fun m -> m "git changes are empty");
            Lwt.return (Some [])
          | Ok changes ->
            commit_id git_kv >>= fun commit_id ->
            modified git_kv >>= fun modified ->
            Logs.info (fun m -> m "git: %s" commit_id);
            let repo = repo commit_id in
            Tarball.of_git repo git_kv >|= fun index ->
            t.commit_id <- commit_id ;
            t.modified <- modified ;
            t.repo <- repo ;
            t.index <- index;
            Some changes)

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
    let dispatch t store hook_url update _flow _conn reqd =
      let request = Httpaf.Reqd.request reqd in
      Logs.info (fun f -> f "requested %s" request.Httpaf.Request.target);
      match String.split_on_char '/' request.Httpaf.Request.target with
      | [ ""; x ] when String.equal x hook_url ->
        Lwt.async update;
        let data = "Update in progress" in
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
            let hash = Mirage_kv.Key.v hash in
            Lwt.async (fun () ->
                (Disk.last_modified store h hash >|= function
                  | Error _ ->
                    Logs.warn (fun m -> m "error retrieving last modified");
                    t.modified
                  | Ok v -> ptime_to_http_date v) >>= fun last_modified ->
                if not_modified request (last_modified, Mirage_kv.Key.basename hash) then
                  let resp = Httpaf.Response.create `Not_modified in
                  respond_with_empty reqd resp;
                  Lwt.return_unit
                else
                  Disk.size store h hash >>= function
                  | Error _ ->
                    Logs.warn (fun m -> m "error retrieving size");
                    not_found reqd request.Httpaf.Request.target;
                    Lwt.return_unit
                  | Ok size ->
                    let size = Optint.Int63.to_string size in
                    let mime_type = "application/octet-stream" in
                    let headers = [
                      "content-type", mime_type ;
                      "etag", Mirage_kv.Key.basename hash ;
                      "last-modified", last_modified ;
                      "content-length", size ;
                    ]
                    in
                    let headers = Httpaf.Headers.of_list headers in
                    let resp = Httpaf.Response.create ~headers `OK in
                    let body = Httpaf.Reqd.respond_with_streaming reqd resp in
                    Disk.read_chunked store h hash (fun () chunk ->
                        let wait, wakeup = Lwt.task () in
                        Httpaf.Body.write_string body chunk;
                        Httpaf.Body.flush body (Lwt.wakeup wakeup);
                        wait) () >|= fun _ ->
                    Httpaf.Body.close_writer body)
        end
      | _ ->
        Logs.warn (fun m -> m "unknown request %s" request.Httpaf.Request.target);
        not_found reqd request.Httpaf.Request.target

  end

  let bad_archives = SSet.of_list Bad.archives

  let download_archives disk http_client store =
    Git.find_urls store >>= fun urls ->
    let urls = SM.filter (fun k _ -> not (SSet.mem k bad_archives)) urls in
    let pool = Lwt_pool.create (Key_gen.parallel_downloads ()) (Fun.const Lwt.return_unit) in
    let idx = ref 0 in
    Lwt_list.iter_p (fun (url, csums) ->
        Lwt_pool.use pool @@ fun () ->
        HM.fold (fun h v r ->
            r >>= function
            | true -> Disk.exists disk h (hex_to_key v)
            | false -> Lwt.return false)
          csums (Lwt.return true) >>= function
        | true ->
          Logs.debug (fun m -> m "ignoring %s (already present)" url);
          Lwt.return_unit
        | false ->
          incr idx;
          if !idx mod 10 = 0 then Gc.full_major () ;
          Logs.info (fun m -> m "downloading %s" url);
          let body _response acc data = Lwt.return (acc ^ data) in
          Http_mirage_client.request http_client url body "" >>= function
          | Ok (resp, body) ->
            if resp.status = `OK then begin
              Logs.info (fun m -> m "downloaded %s" url);
              Disk.write disk ~url body csums
            end else begin
              Logs.warn (fun m -> m "%s: %a (reason %s)"
                            url H2.Status.pp_hum resp.status resp.reason);
              Lwt.return_unit
            end
          | _ -> Lwt.return_unit)
      (SM.bindings urls) >>= fun () ->
    Disk.update_caches disk >|= fun () ->
    Logs.info (fun m -> m "downloading of %d urls done" (SM.cardinal urls))

  let dump_git git_dump git_kv =
    Git_kv.to_octets git_kv >>= fun data ->
    Cache.write git_dump data >|= function
    | Ok () ->
      Logs.info (fun m -> m "dumped git %d bytes" (String.length data))
    | Error e ->
      Logs.warn (fun m -> m "failed to dump git: %a" Cache.pp_write_error e)

  let restore_git git_dump git_ctx =
    Cache.read git_dump >>= function
    | Ok None -> Lwt.return (Error ())
    | Error e ->
      Logs.warn (fun m -> m "failed to read git state: %a" Cache.pp_error e);
      Lwt.return (Error ())
    | Ok Some data ->
      Git_kv.of_octets git_ctx ~remote:(Key_gen.remote ()) data >|= function
      | Ok git_kv -> Ok git_kv
      | Error `Msg msg ->
        Logs.err (fun m -> m "error restoring git state: %s" msg);
        Error ()

  module Paf = Paf_mirage.Make(Stack.TCP)

  let start block _time _pclock stack git_ctx http_ctx =
    BLOCK.get_info block >>= fun info ->
    let sectors_cache = Key_gen.sectors_cache () in
    let sectors_git = Key_gen.sectors_git () in
    let git_start =
      let cache_size = Int64.(mul 2L sectors_cache) in
      Int64.(sub info.size_sectors (add cache_size sectors_git))
    in
    Part.connect git_start block >>= fun (kv, rest) ->
    let git_dump, rest = Part.subpartition sectors_git rest in
    let md5s, sha512s = Part.subpartition sectors_cache rest in
    KV.connect kv >>= fun kv ->
    Cache.connect md5s >>= fun md5s ->
    Cache.connect sha512s >>= fun sha512s ->
    Cache.connect git_dump >>= fun git_dump ->
    Logs.info (fun m -> m "Available bytes in tar storage: %Ld" (KV.free kv));
    Disk.init ~verify_sha256:(Key_gen.verify_sha256 ()) kv md5s sha512s >>= fun disk ->
    if Key_gen.check () then
      Lwt.return_unit
    else
      begin
        Logs.info (fun m -> m "Initializing git state. This may take a while...");
        (if Key_gen.ignore_local_git () then
           Lwt.return (Error ())
         else
           restore_git git_dump git_ctx) >>= function
        | Ok git_kv -> Lwt.return git_kv
        | Error () ->
          Git_kv.connect git_ctx (Key_gen.remote ()) >>= fun git_kv ->
          dump_git git_dump git_kv >|= fun () ->
          git_kv
      end >>= fun git_kv ->
      Logs.info (fun m -> m "Done initializing git state!");
      Serve.commit_id git_kv >>= fun commit_id ->
      Logs.info (fun m -> m "git: %s" commit_id);
      Serve.create git_kv >>= fun serve ->
      Paf.init ~port:(Key_gen.port ()) (Stack.tcp stack) >>= fun t ->
      let update () =
        Serve.update_git serve git_kv >>= function
        | None | Some [] -> Lwt.return_unit
        | Some _changes ->
          dump_git git_dump git_kv >>= fun () ->
          download_archives disk http_ctx git_kv
      in
      let service =
        Paf.http_service
          ~error_handler:(fun _ ?request:_ _ _ -> ())
          (Serve.dispatch serve disk (Key_gen.hook_url ()) update)
      in
      let `Initialized th = Paf.serve service t in
      Logs.info (fun f -> f "listening on %d/HTTP" (Key_gen.port ()));
      Lwt.async (fun () ->
          let rec go () =
            Time.sleep_ns (Duration.of_hour 1) >>= fun () ->
            update () >>= fun () ->
            go ()
          in
          go ());
      download_archives disk http_ctx git_kv >>= fun () ->
      (th >|= fun _v -> ())
end
