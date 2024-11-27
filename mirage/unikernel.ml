open Lwt.Infix

let argument_error = 64

module K = struct
  open Cmdliner

  let check =
    let doc = Arg.info ~doc:"Only check the cache" ["check"] in
    Mirage_runtime.register_arg Arg.(value & flag doc)

  let skip_download =
    let doc = Arg.info ~doc:"Skip downloading archives" ["skip-download"] in
    Mirage_runtime.register_arg Arg.(value & flag doc)

  let upstream_caches =
    let doc =
      "Upstream caches (e.g. https://opam.ocaml.org/cache). \
       For each package first the declared url is attempted. Then, \
       if any, all the declared mirrors are attempted. \
       Finally, the upstream caches are attempted. \
       Note that this does not change the \"archive-mirrors:\" value \
       in the /repo endpoint."
    in
    let doc = Arg.info ~doc ["upstream-cache"] in
    Mirage_runtime.register_arg Arg.(value & opt_all string [] doc)

  let skip_verify_sha256 =
    let doc = Arg.info
        ~doc:"Skip verification of the SHA256 checksums of the cache contents, \
              and do not re-build the other checksum caches."
      ["skip-verify-sha256"]
    in
    Mirage_runtime.register_arg Arg.(value & flag doc)

  let remote =
    let doc = Arg.info
      ~doc:"Remote repository url, use suffix #foo to specify a branch 'foo': \
            https://github.com/ocaml/opam-repository.git"
      ["remote"]
    in
    Mirage_runtime.register_arg
      Arg.(value & opt string "https://github.com/ocaml/opam-repository.git#master" doc)

  let parallel_downloads =
    let doc = Arg.info
        ~doc:"Amount of parallel HTTP downloads"
        ["parallel-downloads"]
    in
    Mirage_runtime.register_arg Arg.(value & opt int 20 doc)

  let hook_url =
    let doc = Arg.info
        ~doc:"URL to conduct an update of the git repository" ["hook-url"]
    in
    Mirage_runtime.register_arg Arg.(value & opt string "update" doc)

  let port =
    let doc = Arg.info ~doc:"HTTP listen port." ["port"] in
    Mirage_runtime.register_arg Arg.(value & opt int 80 doc)

  let cache_size =
    let doc = "Number of MB reserved for each checksum cache (md5, sha512). Only used with --initialize-disk." in
    let doc = Arg.info ~doc ["cache-size"] in
    Mirage_runtime.register_arg Arg.(value & opt int 4 doc)

  let git_size =
    let doc = "Number of MB reserved for git dump. Only used with --initialize-disk" in
    let doc = Arg.info ~doc ["git-size"] in
    Mirage_runtime.register_arg Arg.(value & opt int 40 doc)

  let swap_size =
    let doc = "Number of MB reserved for swap. Only used with --initialize-disk" in
    let doc = Arg.info ~doc ["swap-size"] in
    Mirage_runtime.register_arg Arg.(value & opt int 1024 doc)

  let initialize_disk =
    let doc = "Initialize the disk with a partition table. THIS IS DESTRUCTIVE!" in
    let doc = Arg.info ~doc ["initialize-disk"] in
    Mirage_runtime.register_arg Arg.(value & flag doc)

  let ignore_local_git =
    let doc = "Ignore restoring locally saved git repository." in
    let doc = Arg.info ~doc ["ignore-local-git"] in
    Mirage_runtime.register_arg Arg.(value & flag doc)
end

module Make
  (BLOCK : Mirage_block.S)
  (Time : Mirage_time.S)
  (Pclock : Mirage_clock.PCLOCK)
  (Stack : Tcpip.Stack.V4V6)
  (_ : sig end)
  (HTTP : Http_mirage_client.S) = struct

  module Part = Partitions.Make(BLOCK)
  module KV = Tar_mirage.Make_KV_RW(Pclock)(Part)
  module Cache = OneFFS.Make(Part)
  module Swap = Swapfs.Make(Part)
  module Store = Git_kv.Make(Pclock)

  module SM = Map.Make(String)
  module SSet = Set.Make(String)

  let compare_hash = Archive_checksum.Hash.compare

  module HM = Archive_checksum.HM

  let hash_to_string = Archive_checksum.Hash.to_string

  let hash_of_string = Archive_checksum.Hash.of_string

  let hex_to_key h = Mirage_kv.Key.v (Ohex.encode h)

  let hm_to_s hm =
    HM.fold (fun h v acc ->
        hash_to_string h ^ "=" ^ Ohex.encode v ^ "\n" ^ acc)
      hm ""

  let parse_errors = ref SM.empty

  let reset_parse_errors () = parse_errors := SM.empty

  let add_parse_error filename error =
    parse_errors := SM.add filename error !parse_errors

  module Git = struct
    let contents store =
      let explore = ref [ Mirage_kv.Key.empty ] in
      let more () =
        let rec go () =
          match !explore with
          | [] -> Lwt.return None
          | step :: tl ->
            explore := tl;
            Store.exists store step >>= function
            | Error e -> go ()
            | Ok None -> go ()
            | Ok Some `Value -> Lwt.return (Some step)
            | Ok Some `Dictionary ->
              Store.list store step >>= function
              | Error e -> go ()
              | Ok steps ->
                explore := List.map fst steps @ !explore;
                go ()
        in
        go ()
      in
      Lwt_stream.from more

    let sha256s = Hashtbl.create 13

    let empty () = Hashtbl.clear sha256s

    let find_urls acc path data =
      if Mirage_kv.Key.basename path = "opam" then
        let path = Mirage_kv.Key.to_string path in
        let url_csums, errs = Opam_file.extract_urls path data in
        List.iter (fun (`Msg msg) -> add_parse_error path msg) errs;
        let upstream hm =
          HM.fold
          (fun hash hash_value set ->
              List.fold_left (fun set cache_url ->
                  let url =
                    cache_url ^ "/" ^ Archive_checksum.Hash.to_string hash ^
                    "/" ^ String.sub hash_value 0 2 ^ "/" ^ hash_value
                  in
                  SSet.add url set)
                set (K.upstream_caches ()))
            hm SSet.empty
        in
        List.fold_left (fun acc (url, csums, mirrors) ->
            if HM.cardinal csums = 0 then
              (add_parse_error path ("no checksums for " ^ url);
               acc)
            else begin
              let url' =
                match HM.find_opt `SHA256 csums with
                | None -> url
                | Some hash ->
                  match Hashtbl.find_opt sha256s hash with
                  | None -> Hashtbl.add sha256s hash url; url
                  | Some url' ->
                    if not (String.equal url url') then
                      Logs.debug (fun m -> m "same hash for url %s and %s" url url');
                    url'
              in
              let mirrors = SSet.of_list mirrors in
              let url, mirrors =
                if String.equal url url' then
                  url, mirrors
                else
                  url', SSet.add url mirrors
              in
              SM.update url (function
                  | None -> Some (csums, mirrors, upstream csums)
                  | Some (csums', mirrors', upstream_caches') ->
                    if HM.for_all (fun h v ->
                        match HM.find_opt h csums with
                        | None -> true | Some v' -> String.equal v v')
                        csums'
                    then
                      Some (HM.union (fun _h v _v' -> Some v) csums csums',
                            SSet.union mirrors mirrors',
                            SSet.union (upstream csums) upstream_caches'
                           )
                    else begin
                      add_parse_error path (Fmt.str
                                              "mismatching hashes for %s: %s vs %s"
                                              url (hm_to_s csums') (hm_to_s csums));
                      None
                    end) acc
            end) acc url_csums
      else
        acc

  end

  let active_downloads = ref SM.empty

  let add_to_active url ts =
    active_downloads := SM.add url (ts, 0) !active_downloads

  let remove_active url =
    active_downloads := SM.remove url !active_downloads

  let active_add_bytes url written =
    match SM.find_opt url !active_downloads with
    | None -> ()
    | Some (ts, written') ->
      active_downloads := SM.add url (ts, written + written')
          !active_downloads

  let failed_downloads = ref SM.empty

  let reset_failed_downloads () = failed_downloads := SM.empty

  let add_failed url ts reason =
    remove_active url;
    failed_downloads := SM.add url (ts, reason) !failed_downloads

  let pp_failed ppf = function
    | `Write_error e ->
      KV.pp_write_error ppf e
    | `Swap e ->
      Swap.pp_error ppf e
    | `Bad_checksum (hash, computed, expected) ->
      Fmt.pf ppf "%s checksum: computed %s expected %s"
        (hash_to_string hash)
        (Ohex.encode computed)
        (Ohex.encode expected)
    | `Bad_response (status, reason) ->
      Fmt.pf ppf "%a %s" H2.Status.pp_hum status reason
    | `Mimic me ->
      Mimic.pp_error ppf me

  let key_of_failed = function
    | `Write_error _ -> `Write_error
    | `Swap _ -> `Swap
    | `Bad_checksum _ -> `Bad_checksum
    | `Bad_response _ -> `Bad_response
    | `Mimic _ -> `Mimic

  let compare_failed_key a b = match a, b with
    | `Write_error, `Write_error -> 0
    | `Write_error, _ -> -1
    | _, `Write_error -> 1
    | `Swap, `Swap -> 0
    | `Swap, _ -> -1
    | _, `Swap -> 1
    | `Bad_checksum, `Bad_checksum -> 0
    | `Bad_checksum, _ -> -1
    | _, `Bad_checksum -> 1
    | `Bad_response, `Bad_response -> 0
    | `Bad_response, _ -> -1
    | _, `Bad_response -> 1
    | `Mimic, `Mimic -> 0

  let pp_key ppf = function
    | `Write_error -> Fmt.pf ppf "Write error"
    | `Swap -> Fmt.pf ppf "Swap error"
    | `Bad_checksum -> Fmt.pf ppf "Bad checksum"
    | `Bad_response -> Fmt.pf ppf "Bad response"
    | `Mimic -> Fmt.pf ppf "Mimic"

  let remaining_downloads = ref 0

  let archives = ref 0

  let last_git = ref Ptime.epoch

  let last_git_status = ref (Error "unknown")

  module Disk = struct
    module KS = Set.Make(Mirage_kv.Key)

    type t = {
      mutable md5s : string SM.t ;
      mutable sha512s : string SM.t ;
      mutable checked : KS.t option ;
      dev : KV.t ;
      dev_md5s : Cache.t ;
      dev_sha512s : Cache.t ;
      dev_swap : Swap.t ;
    }

    let empty dev dev_md5s dev_sha512s dev_swap =
      { md5s = SM.empty ; sha512s = SM.empty ; checked = Some KS.empty ; dev; dev_md5s; dev_sha512s ; dev_swap }

    let add_checked t path =
      match t.checked with
      | None -> ()
      | Some s -> t.checked <- Some (KS.add path s)

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
       | Ok () -> ()
       | Error e -> Logs.warn (fun m -> m "Failed to write 'md5s': %a" Cache.pp_write_error e));
      Cache.write t.dev_sha512s (marshal_sm t.sha512s) >>= fun r ->
      match r with
      | Ok () -> Lwt.return_unit
      | Error e ->
        Logs.warn (fun m -> m "Failed to write 'sha512s': %a" Cache.pp_write_error e);
        Lwt.return_unit

    let find_key t h key =
      if List.length (Mirage_kv.Key.segments key) <> 1 then begin
        Logs.warn (fun m -> m "find_key with multiple segments: %a" Mirage_kv.Key.pp key);
        Error `Not_found
      end else
        match
          match h with
          | `MD5 ->
            Option.map Mirage_kv.Key.v (SM.find_opt (Mirage_kv.Key.basename key) t.md5s)
          | `SHA512 ->
            Option.map Mirage_kv.Key.v (SM.find_opt (Mirage_kv.Key.basename key) t.sha512s)
          | `SHA256 -> Some key
        with
        | None -> Error `Not_found
        | Some x -> Ok x

    let ready t h key =
      match t.checked with
      | None -> true
      | Some s -> match find_key t h key with
        | Ok k -> KS.mem k s
        | Error _ -> false

    let completely_checked t = t.checked = None

    let read_chunked t h v f a =
      match find_key t h v with
      | Error `Not_found ->
        Lwt.return (Error (`Not_found v))
      | Ok key ->
        KV.size t.dev key >>= function
        | Error e ->
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
                Lwt.return (Error e)
            else
              Lwt.return (Ok a)
          in
          read_more a Optint.Int63.zero

    let init_write t csums =
      let quux, csums = Archive_checksum.init_write csums in
      let swap = Swap.empty t.dev_swap in
      quux, Ok (csums, swap)

    let write_partial t (hash, csum) url =
      (* XXX: we may be in trouble if different hash functions are used for the same archive *)
      let ( >>>= ) = Lwt_result.bind in
      fun response r data ->
        if Http_mirage_client.Status.is_successful response.Http_mirage_client.status then
          Lwt.return r >>>= fun (digests, swap) ->
          let digests = Archive_checksum.update_digests digests data in
          active_add_bytes url (String.length data);
          Swap.append swap data >|= function
          | Ok () -> Ok (digests, swap)
          | Error swap_err -> Error (`Swap swap_err)
        else
          Lwt.return (Error `Bad_response)

    let check_csums_digests csums digests =
      let csums' = Archive_checksum.digests_to_hm digests in
      let common_bindings = List.filter (fun (h, _) -> HM.mem h csums) (HM.bindings csums') in
      List.length common_bindings > 0 &&
      List.for_all
        (fun (h, csum) -> String.equal csum (HM.find h csums))
        common_bindings

    let set_from_handle dev dest h =
      (* TODO: we need a function in tar which
         (a) takes a path
         (b) takes a function that reads (from the swap) and writes (to the tar)
         (c) once the function is finished, it writes the tar header
         -> this would allow us to avoid the rename stuff below
      *)
      let size = Optint.Int63.of_int64 (Swap.size h) in
      KV.allocate dev dest size >>= fun r ->
      let rec loop offset =
        if offset = Swap.size h then
          Lwt.return_ok ()
        else
          let length = Int64.(to_int (min 4096L (sub (Swap.size h) offset))) in
          Swap.get_partial h ~offset ~length >>= fun r ->
          match r with
          | Error e -> Lwt.return (Error (`Swap e))
          | Ok data ->
            KV.set_partial dev dest ~offset:(Optint.Int63.of_int64 offset) data
            >>= fun r ->
            match r with
            | Error e -> Lwt.return (Error (`Write_error e))
            | Ok () ->
              loop Int64.(add offset (of_int length))
      in
      match r with
      | Ok () ->
        loop 0L
      | Error e ->
        Lwt.return (Error (`Write_error e))

    let finalize_write t (hash, csum) ~url swap csums digests =
      if check_csums_digests csums digests then
        let sha256 = Ohex.encode Digestif.SHA256.(to_raw_string (get digests.sha256))
        and md5 = Ohex.encode Digestif.MD5.(to_raw_string (get digests.md5))
        and sha512 = Ohex.encode Digestif.SHA512.(to_raw_string (get digests.sha512)) in
        let dest = Mirage_kv.Key.v sha256 in
        let temp = Mirage_kv.Key.(v "pending" // dest) in
        Lwt_result.bind
          (Lwt.finalize (fun () -> set_from_handle t.dev temp swap)
             (fun () -> Swap.free swap))
          (fun () -> KV.rename t.dev ~source:temp ~dest
                     |> Lwt_result.map_error (fun e -> `Write_error e))
        >|= function
        | Ok () ->
          remove_active url;
          t.md5s <- SM.add md5 sha256 t.md5s;
          t.sha512s <- SM.add sha512 sha256 t.sha512s;
          add_checked t dest
        | Error `Write_error e -> add_failed url (Ptime.v (Pclock.now_d_ps ())) (`Write_error e)
        | Error `Swap e -> add_failed url (Ptime.v (Pclock.now_d_ps ())) (`Swap e)
      else begin
        add_failed url (Ptime.v (Pclock.now_d_ps ()))
          (`Bad_checksum (hash, Archive_checksum.get digests hash, csum));
        Lwt.return_unit
      end

    (* on disk, we use a flat file system where the filename is the sha256 of the data *)
    let check ~skip_verify_sha256 t =
      KV.list t.dev Mirage_kv.Key.empty >>= function
      | Error e ->
        Logs.err (fun m -> m "error %a listing kv" KV.pp_error e);
        Lwt.return_unit
      | Ok entries ->
        Cache.read t.dev_md5s >>= fun r ->
        (match r with
         | Ok Some s ->
           if skip_verify_sha256 then
             Result.iter (fun md5s -> t.md5s <- md5s) (unmarshal_sm s)
         | Ok None -> ()
         | Error e -> Logs.warn (fun m -> m "Error reading md5s cache: %a" Cache.pp_error e));
        Cache.read t.dev_sha512s >>= fun r ->
        (match r with
         | Ok Some s ->
           if skip_verify_sha256 then
             Result.iter (fun sha512s -> t.sha512s <- sha512s) (unmarshal_sm s)
         | Ok None -> ()
         | Error e -> Logs.warn (fun m -> m "Error reading sha512s cache: %a" Cache.pp_error e));
        let md5s = SSet.of_list (List.map snd (SM.bindings t.md5s))
        and sha512s = SSet.of_list (List.map snd (SM.bindings t.sha512s)) in
        Lwt_list.iter_s (fun (path, typ) ->
            match typ with
            | `Dictionary -> Lwt.return_unit
            | `Value ->
              let open Digestif in
              let md5_final =
                if not (SSet.mem (Mirage_kv.Key.basename path) md5s) then
                  let f s =
                    let digest = MD5.(to_raw_string (get s)) in
                    t.md5s <- SM.add (Ohex.encode digest) (Mirage_kv.Key.basename path) t.md5s
                  in
                  Some f
                else
                  None
              and sha512_final =
                if not (SSet.mem (Mirage_kv.Key.basename path) sha512s) then
                  let f s =
                    let digest = SHA512.(to_raw_string (get s)) in
                    t.sha512s <- SM.add (Ohex.encode digest) (Mirage_kv.Key.basename path) t.sha512s
                  in
                  Some f
                else
                  None
              in
              let sha256_final =
                let need_to_compute = md5_final <> None || sha512_final <> None || not skip_verify_sha256 in
                if need_to_compute then
                  let f s =
                    let digest = SHA256.(to_raw_string (get s)) in
                    if not (String.equal (Mirage_kv.Key.basename path) (Ohex.encode digest)) then
                      begin
                        Logs.err (fun m -> m "corrupt SHA256 data for %a, \
                                              computed %s (will rename)"
                                     Mirage_kv.Key.pp path (Ohex.encode digest));
                        false
                      end else true
                  in
                  Some f
                else
                  None
              in
              match sha256_final with
              | None ->
                add_checked t path;
                Lwt.return_unit
              | Some f ->
                read_chunked t `SHA256 path
                  (fun (sha256, md5, sha512) data ->
                     let sha256 = SHA256.feed_string sha256 data in
                     Lwt.pause () >>= fun () ->
                     let md5 =
                       Option.map (fun t -> MD5.feed_string t data) md5
                     in
                     Lwt.pause () >>= fun () ->
                     let sha512 =
                       Option.map (fun t -> SHA512.feed_string t data) sha512
                     in
                     Lwt.pause () >|= fun () ->
                     sha256, md5, sha512)
                  (SHA256.empty,
                   Option.map (fun _ -> MD5.empty) md5_final,
                   Option.map (fun _ -> SHA512.empty) sha512_final) >>= function
                | Error e ->
                  Logs.err (fun m -> m "error %a of %a while computing digests"
                               KV.pp_error e Mirage_kv.Key.pp path);
                  Lwt.return_unit
                | Ok (sha256, md5, sha512) ->
                  if not (f sha256) then
                    (* bad sha256! *)
                    KV.rename t.dev ~source:path ~dest:(Mirage_kv.Key.(v "delete" // path)) >|= function
                    | Ok () -> ()
                    | Error we ->
                      Logs.err (fun m -> m "error %a while renaming %a" KV.pp_write_error we
                                   Mirage_kv.Key.pp path)
                  else begin
                    Option.iter (fun f -> f (Option.get md5)) md5_final;
                    Option.iter (fun f -> f (Option.get sha512)) sha512_final;
                    add_checked t path;
                    Lwt.return_unit
                  end)
          entries >>= fun () ->
        update_caches t >|= fun () ->
        t.checked <- None

    let exists t h v =
      match find_key t h v with
      | Error _ -> Lwt.return false
      | Ok x ->
        KV.exists t.dev x >|= function
        | Ok Some `Value -> true
        | Ok Some `Dictionary -> false
        | Ok None -> false
        | Error _ -> false

    let last_modified t h v =
      match find_key t h v with
      | Error _ as e -> Lwt.return e
      | Ok x ->
        KV.last_modified t.dev x >|= function
        | Ok data -> Ok data
        | Error _ -> Error `Not_found

    let size t h v =
      match find_key t h v with
      | Error _ as e -> Lwt.return e
      | Ok x ->
        KV.size t.dev x >|= function
        | Ok s -> Ok s
        | Error _ -> Error `Not_found
    end

  module Tarball = struct
    module High : sig
      type t
      type 'a s = 'a Lwt.t

      external inj : 'a s -> ('a, t) Tar.io = "%identity"
      external prj : ('a, t) Tar.io -> 'a s = "%identity"
    end = struct
      type t
      type 'a s = 'a Lwt.t

      external inj : 'a -> 'b = "%identity"
      external prj : 'a -> 'b = "%identity"
    end

    let to_buffer buf t =
      let rec run : type a. (a, [> `Msg of string ] as 'err, High.t) Tar.t -> (a, 'err) result Lwt.t
        = function
        | Tar.Write str ->
          Buffer.add_string buf str;
          Lwt.return_ok ()
        | Tar.Read _ -> assert false
        | Tar.Really_read _ -> assert false
        | Tar.Seek _ -> assert false
        | Tar.Return value -> Lwt.return value
        | Tar.High value -> High.prj value
        | Tar.Bind (x, f) ->
            let open Lwt_result.Infix in
            run x >>= fun value -> run (f value) in
      run t

    let once data =
      let closed = ref false in
      fun () -> if !closed
        then Tar.High (High.inj (Lwt.return_ok None))
        else begin closed := true; Tar.High (High.inj (Lwt.return_ok (Some  data))) end

    let entries_of_git ~mtime store repo urls =
      let entries = Git.contents store in
      let to_entry path =
        match Mirage_kv.Key.segments path with
        (* from opam source code, src/repository/opamHTTP.ml:
           include only three top-level dirs/files: packages, version, repo *)
        | "packages" :: _
        | "version" :: _
        | "repo" :: _ ->
          begin
            Store.get store path >|= function
            | Ok data ->
              let data =
                if Mirage_kv.Key.(equal path (v "repo"))
                then repo else data
              in
              let file_mode = 0o644
              and mod_time = Int64.of_int mtime
              and user_id = 0
              and group_id = 0
              and size = String.length data in
              let hdr = Tar.Header.make ~file_mode ~mod_time ~user_id ~group_id
                  (Mirage_kv.Key.to_string path) (Int64.of_int size) in
              urls := Git.find_urls !urls path data;
              Some (Some Tar.Header.Ustar, hdr, once data)
            | Error _ -> None
          end
        | _ -> Lwt.return None
      in
      let entries = Lwt_stream.filter_map_s to_entry entries in
      Lwt.return begin fun () -> Tar.High (High.inj (Lwt_stream.get entries >|= Result.ok)) end

    let of_git repo store =
      let now = Ptime.v (Pclock.now_d_ps ()) in
      let mtime = Option.value ~default:0 Ptime.(Span.to_int_s (to_span now)) in
      let urls = ref SM.empty in
      entries_of_git ~mtime store repo urls >>= fun entries ->
      Git.empty ();
      let t = Tar.out ~level:Ustar entries in
      let t = Tar_gz.out_gzipped ~level:4 ~mtime:(Int32.of_int mtime) Gz.Unix t in
      let buf = Buffer.create 1024 in
      to_buffer buf t >|= function
      | Ok () -> Buffer.contents buf, !urls
      | Error (`Msg msg) -> failwith msg
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
      Result.fold r ~ok:Ohex.encode
        ~error:(fun e ->
            Logs.err (fun m -> m "%a" Store.pp_error e);
            exit 2)

    let repo remote commit =
      let upstream = List.hd (String.split_on_char '#' remote) in
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

    let create remote git_kv =
      commit_id git_kv >>= fun commit_id ->
      modified git_kv >>= fun modified ->
      let repo = repo remote commit_id in
      Tarball.of_git repo git_kv >|= fun (index, urls) ->
      { commit_id ; modified ; repo ; index }, urls

    let update_lock = Lwt_mutex.create ()

    let update_git ~remote t git_kv =
      Lwt_mutex.with_lock update_lock (fun () ->
          Logs.info (fun m -> m "pulling the git repository");
          last_git := Ptime.v (Pclock.now_d_ps ());
          Git_kv.pull git_kv >>= function
          | Error `Msg msg ->
            Logs.err (fun m -> m "error %s while updating git" msg);
            last_git_status := Error msg;
            Lwt.return None
          | Ok [] ->
            Logs.info (fun m -> m "git changes are empty");
            last_git_status := Ok 0;
            Lwt.return (Some ([], SM.empty))
          | Ok changes ->
            last_git_status := Ok (List.length changes);
            commit_id git_kv >>= fun commit_id ->
            modified git_kv >>= fun modified ->
            Logs.info (fun m -> m "git: %s" commit_id);
            let repo = repo remote commit_id in
            reset_parse_errors ();
            Tarball.of_git repo git_kv >|= fun (index, urls) ->
            t.commit_id <- commit_id ;
            t.modified <- modified ;
            t.repo <- repo ;
            t.index <- index;
            Some (changes, urls))

    let status t disk =
      (* report status:
         - archive size (can we easily measure?) and number of "good" elements
      *)
      let archive_stats =
        Fmt.str "<ul><li>commit %s</li><li>last modified (of index.tar.gz) %s</li><li>repo %s</li><li>%u validated archives on disk</li><li>%Lu bytes free</li><li>%u URLs identified</li><li>%u downloads are remaining</li><li>last git fetch %s</li><li>last git status: %s</li></ul>"
          t.commit_id t.modified (K.remote ())
          (SM.cardinal disk.Disk.md5s)
          (KV.free disk.Disk.dev)
          !archives
          !remaining_downloads
          (ptime_to_http_date !last_git)
          (match !last_git_status with Ok x -> "ok with " ^ string_of_int x ^ " changes" | Error msg -> "error " ^ msg)
      in
      let sort_by_ts a b = Ptime.compare b a in
      let active_downloads =
        let header = "<h2>Active downloads</h2><ul>" in
        let content =
          SM.bindings !active_downloads |>
          List.sort (fun (_, (a, _)) (_, (b, _)) -> sort_by_ts a b) |>
          List.map (fun (url, (ts, bytes_written)) ->
              "<li>" ^ Ptime.to_rfc3339 ?tz_offset_s:None ts ^ ": " ^ url ^ " " ^ string_of_int bytes_written ^ " bytes written to swap</li>")
        in
        header ^ String.concat "" content ^ "</ul>"
      and failed_downloads =
        let header = "<h2>Failed downloads</h2>" in
        let group_by xs =
          let t = Hashtbl.create 7 in
          List.iter (fun ((_, (_, reason)) as e) ->
              let k = key_of_failed reason in
              let els = Option.value ~default:[] (Hashtbl.find_opt t k) in
              Hashtbl.replace t k (e :: els))
            xs;
          Hashtbl.fold (fun k els acc ->
              let sorted =
                List.sort (fun (_, (tsa, _)) (_, (tsb, _)) ->
                    sort_by_ts tsa tsb)
                  els
              in
              (k, sorted) :: acc)
            t []
        in
        let content =
          SM.bindings !failed_downloads |>
          group_by |>
          List.sort (fun (a, _) (b, _) -> compare_failed_key a b) |>
          List.map (fun (key, els) ->
              let header = Fmt.str "<h3>%a</h3><ul>" pp_key key in
              let content =
                List.map (fun (url, (ts, reason)) ->
                    Fmt.str "<li>%s: %s error %a"
                      (Ptime.to_rfc3339 ?tz_offset_s:None ts) url pp_failed reason)
                  els
              in
              header ^ String.concat "" content ^ "</ul>")
        in
        header ^ String.concat "" content
      and parse_errors =
        let header = "<h2>Parse errors</h2><ul>" in
        let content =
          SM.bindings !parse_errors |>
          List.sort (fun (a, _) (b, _) -> String.compare a b) |>
          List.map (fun (filename, reason) ->
              "<li>" ^ filename ^ ": " ^ reason ^ "</li>")
        in
        header ^ String.concat "" content ^ "</ul>"
      in
      "<html><head><title>Opam-mirror status page</title></head><body><h1>Opam mirror status</h1><div>"
      ^ String.concat "</div><div>" [ archive_stats ; active_downloads ; failed_downloads ; parse_errors ]
        ^ "</div></body></html>"

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
      | [ ""; x ] when String.equal x "status" ->
        let data = status t store in
        let mime_type = "text/html" in
        let headers = [
          "content-type", mime_type ;
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
            not_found reqd request.Httpaf.Request.target
          | Ok h ->
            let hash = Mirage_kv.Key.v hash in
            Lwt.async (fun () ->
                if Disk.ready store h hash then
                  (Disk.last_modified store h hash >|= function
                    | Error _ -> t.modified
                    | Ok v -> ptime_to_http_date v) >>= fun last_modified ->
                  if not_modified request (last_modified, Mirage_kv.Key.basename hash) then
                    let resp = Httpaf.Response.create `Not_modified in
                    respond_with_empty reqd resp;
                    Lwt.return_unit
                  else
                    Disk.size store h hash >>= function
                    | Error _ ->
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
                          (* FIXME: catch exception when body is closed *)
                          Httpaf.Body.write_string body chunk;
                          Httpaf.Body.flush body (Lwt.wakeup wakeup);
                          wait) () >|= fun _ ->
                      Httpaf.Body.close_writer body
                else begin
                  not_found reqd request.Httpaf.Request.target;
                  Lwt.return_unit
                end)
        end
      | _ ->
        Logs.warn (fun m -> m "unknown request %s" request.Httpaf.Request.target);
        not_found reqd request.Httpaf.Request.target

  end

  let download_archives parallel_downloads disk http_client urls =
    reset_failed_downloads ();
    remaining_downloads := SM.cardinal urls;
    archives := SM.cardinal urls;
    let pool = Lwt_pool.create parallel_downloads (Fun.const Lwt.return_unit) in
    Lwt_list.iter_p (fun (url, (csums, mirrors, upstream_caches)) ->
        Lwt_pool.use pool @@ fun () ->
        HM.fold (fun h v r ->
            r >>= function
            | true -> Disk.exists disk h (hex_to_key v)
            | false -> Lwt.return false)
          csums (Lwt.return true) >>= function
        | true ->
          decr remaining_downloads;
          Lwt.return_unit
        | false ->
          let rec download url mirrors upstream_caches =
            let retry () =
              if SSet.is_empty mirrors && SSet.is_empty upstream_caches then begin
                decr remaining_downloads;
                Lwt.return_unit
              end else if SSet.is_empty mirrors then
                let elt, upstream_caches =
                  let e = SSet.min_elt upstream_caches in
                  e, SSet.remove e upstream_caches
                in
                download elt mirrors upstream_caches
              else
                let elt, mirrors =
                  let e = SSet.min_elt mirrors in
                  e, SSet.remove e mirrors
                in
                download elt mirrors upstream_caches
            in
            let quux, body_init = Disk.init_write disk csums in
            add_to_active url (Ptime.v (Pclock.now_d_ps ()));
            if not (K.skip_download ()) then
              Http_mirage_client.request http_client url (Disk.write_partial disk quux url) body_init >>= function
              | Ok (resp, r) ->
                begin match r with
                  | Error `Bad_response ->
                    add_failed url (Ptime.v (Pclock.now_d_ps ()))
                      (`Bad_response (resp.status, resp.reason));
                    retry ()
                  | Error `Write_error e ->
                    add_failed url (Ptime.v (Pclock.now_d_ps ())) (`Write_error e);
                    retry ()
                  | Error `Swap e ->
                    add_failed url (Ptime.v (Pclock.now_d_ps ())) (`Swap e);
                    retry ()
                  | Ok (digests, body) ->
                    decr remaining_downloads;
                    Disk.finalize_write disk quux ~url body csums digests
                end
              | Error me ->
                add_failed url (Ptime.v (Pclock.now_d_ps ())) (`Mimic me);
                retry ()
            else
              retry ()
          in
          download url mirrors upstream_caches)
      (SM.bindings urls) >>= fun () ->
    Disk.update_caches disk >|= fun () ->
    Logs.info (fun m -> m "downloading of %d urls done" (SM.cardinal urls))

  let dump_git git_dump git_kv =
    let stream = Git_kv.to_octets git_kv in
    Lwt_stream.to_list stream >>= fun datas ->
    let data = String.concat "" datas in
    Cache.write git_dump data >|= function
    | Ok () ->
      Logs.info (fun m -> m "dumped git %d bytes" (String.length data))
    | Error e ->
      Logs.warn (fun m -> m "failed to dump git: %a" Cache.pp_write_error e)

  let restore_git ~remote git_dump git_ctx =
    Cache.read git_dump >>= function
    | Ok None -> Lwt.return (Error ())
    | Error e ->
      Logs.warn (fun m -> m "failed to read git state: %a" Cache.pp_error e);
      Lwt.return (Error ())
    | Ok Some data ->
      let stream = Lwt_stream.return data in
      Git_kv.of_octets git_ctx ~remote stream >|= function
      | Ok git_kv -> Ok git_kv
      | Error `Msg msg ->
        Logs.err (fun m -> m "error restoring git state: %s" msg);
        Error ()

  module Paf = Paf_mirage.Make(Stack.TCP)

  let start_mirror { Part.tar; swap; git_dump; md5s; sha512s } stack git_ctx http_ctx =
    KV.connect tar >>= fun kv ->
    Cache.connect git_dump >>= fun git_dump ->
    Cache.connect md5s >>= fun md5s ->
    Cache.connect sha512s >>= fun sha512s ->
    Swap.connect swap >>= fun swap ->
    Logs.info (fun m -> m "Available bytes in tar storage: %Ld" (KV.free kv));
    let disk = Disk.empty kv md5s sha512s swap in
    let remote = K.remote () in
    if K.check () then
      Disk.check ~skip_verify_sha256:(K.skip_verify_sha256 ()) disk
    else
      begin
        Logs.info (fun m -> m "Initializing git state. This may take a while...");
        (if K.ignore_local_git () then
           Lwt.return (Error ())
         else
           restore_git ~remote git_dump git_ctx) >>= function
        | Ok git_kv -> Lwt.return (false, git_kv)
        | Error () ->
          Git_kv.connect git_ctx remote >>= fun git_kv ->
          Lwt.return (true, git_kv)
      end >>= fun (need_dump, git_kv) ->
      Logs.info (fun m -> m "Done initializing git state!");
      Serve.commit_id git_kv >>= fun commit_id ->
      Logs.info (fun m -> m "git: %s" commit_id);
      Serve.create remote git_kv >>= fun (serve, urls) ->
      Paf.init ~port:(K.port ()) (Stack.tcp stack) >>= fun t ->
      let update () =
        if Disk.completely_checked disk then
          Serve.update_git ~remote serve git_kv >>= function
          | None | Some ([], _) -> Lwt.return_unit
          | Some (_changes, urls) ->
            dump_git git_dump git_kv >>= fun () ->
            download_archives (K.parallel_downloads ()) disk http_ctx urls
        else begin
          Logs.warn (fun m -> m "disk is not ready yet, thus not updating");
          Lwt.return_unit
        end
      in
      let service =
        Paf.http_service
          ~error_handler:(fun _ ?request:_ _ _ -> ())
          (Serve.dispatch serve disk (K.hook_url ()) update)
      in
      let `Initialized th = Paf.serve service t in
      Logs.info (fun f -> f "listening on %d/HTTP" (K.port ()));
      Lwt.join [
        (if need_dump then begin
            Logs.info (fun m -> m "dumping git state %s" commit_id);
            dump_git git_dump git_kv
         end else
           Lwt.return_unit) ;
        (Disk.check ~skip_verify_sha256:(K.skip_verify_sha256 ()) disk)
      ] >>= fun () ->
      Lwt.async (fun () ->
          let rec go () =
            Time.sleep_ns (Duration.of_hour 1) >>= fun () ->
            update () >>= fun () ->
            go ()
          in
          go ());
      download_archives (K.parallel_downloads ()) disk http_ctx urls >>= fun () ->
      (th >|= fun _v -> ())

  let start block _time _pclock stack git_ctx http_ctx =
    let initialize_disk = K.initialize_disk ()
    and cache_size = K.cache_size ()
    and git_size = K.git_size ()
    and swap_size = K.swap_size () in
    if initialize_disk then
      Part.format block ~cache_size ~git_size ~swap_size >>= function
      | Ok () ->
        Logs.app (fun m -> m "Successfully initialized the disk! You may restart now without --initialize-disk.");
        Lwt.return_unit
      | Error `Msg e ->
        Logs.err (fun m -> m "Error formatting disk: %s" e);
        exit Mirage_runtime.argument_error
      | Error `Block e ->
        Logs.err (fun m -> m "Error formatting disk: %a" BLOCK.pp_write_error e);
        exit 2
    else
      Part.connect block >>= fun parts ->
      start_mirror parts stack git_ctx http_ctx
end
