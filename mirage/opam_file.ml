module HM = Archive_checksum.HM

let hash_to_string = Archive_checksum.Hash.to_string

let hex_of_string s =
  match Ohex.decode s with
  | d -> Ok d
  | exception Invalid_argument err -> Error (`Msg err)

let decode_digest filename str =
  let hex h s =
    match hex_of_string s with
    | Ok d -> Ok (h, d)
    | Error _ as e -> e
  in
  match String.split_on_char '=' str with
  | [ data ] -> hex `MD5 data
  | [ "md5" ; data ] -> hex `MD5 data
  | [ "sha256" ; data ] -> hex `SHA256 data
  | [ "sha512" ; data ] -> hex `SHA512 data
  | [ hash ; _ ] -> Error (`Msg ("unknown hash " ^ hash))
  | _ -> Error (`Msg ("unexpected hash format " ^ str))

let extract_url_checksum filename items =
  let open OpamParserTypes.FullPos in
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
  and mirrors =
    List.find_opt
      (function { pelem = Variable ({ pelem = "mirrors" ; _ }, _); _ } -> true | _ -> false)
      items
  in
  let url =
    match url, archive with
    | Some { pelem = Variable (_, { pelem = String url ; _ }) ; _ }, None -> Ok url
    | None, Some { pelem = Variable (_, { pelem = String url ; _ }); _ } -> Ok url
    | _ -> Error (`Msg "neither 'src' nor 'archive' present")
  and mirrors = match mirrors with
    | None -> []
    | Some { pelem = Variable (_, { pelem = String url ; _ }) ; _ } -> [ url ]
    | Some { pelem = Variable (_, { pelem = List { pelem = urls ; _ } ; _ }) } ->
      List.fold_left (fun acc -> function
          | { pelem = String url ; _ } -> url :: acc
          | v ->
            Logs.err (fun m -> m "bad mirror data (expected a string in the list): %s"
                         (OpamPrinter.FullPos.value v));
            acc)
        [] urls
    | Some v ->
      Logs.err (fun m -> m "bad mirror data (expected string or string list): %s"
                   (OpamPrinter.FullPos.items [ v ]));
      []
  in
  let csum, csum_errs =
    match checksum with
    | Some { pelem = Variable (_, { pelem = List { pelem = csums ; _ } ; _ }); _ } ->
      let csums, errs =
        List.fold_left (fun (csums, errs) ->
            function
            | { pelem = String csum ; _ } ->
              begin match decode_digest filename csum with
                | Error e -> csums, e :: errs
                | Ok (h, v) ->
                  HM.update h (function
                      | None -> Some v
                      | Some v' when String.equal v v' -> None
                      | Some v' ->
                        Logs.warn (fun m -> m "for %s, hash %s, multiple keys are present: %s %s"
                                      (Result.value ~default:"NONE" url) (hash_to_string h) (Ohex.encode v) (Ohex.encode v'));
                        None)
                    csums, errs
              end
            | v ->
              csums, `Msg (Fmt.str "bad checksum data: %s" (OpamPrinter.FullPos.value v)) :: errs)
          (HM.empty, []) csums
      in
      if HM.is_empty csums then
        match errs with
        | hd :: tl -> Error hd, tl
        | [] -> Error (`Msg "empty checksums"), []
      else
        Ok csums, errs
    | Some { pelem = Variable (_, { pelem = String csum ; _ }) ; _ } ->
      begin match decode_digest filename csum with
        | Error _ as e -> e, []
        | Ok (h, v) -> Ok (HM.singleton h v), []
      end
    | _ -> Error (`Msg "couldn't find or decode 'checksum'"), []
  in
  (match url, csum with
   | Ok url, Ok csum -> Ok (url, csum, mirrors)
   | Error _ as e, _
   | _, (Error _ as e) -> e), csum_errs

let extract_checksums_and_urls filename opam =
  let open OpamParserTypes.FullPos in
  List.fold_left (fun (csum_urls, errs) ->
      function
      | { pelem = Section ({ section_kind = { pelem = "url" ; _ } ; section_items = { pelem = items ; _ } ; _ }) ; _} ->
        begin match extract_url_checksum filename items with
          | Error `Msg msg, errs' -> csum_urls, `Msg ("url: " ^ msg) :: errs' @ errs
          | Ok url, errs' -> url :: csum_urls, errs' @ errs
        end
      | { pelem = Section ({ section_kind = { pelem = "extra-source" ; _ } ; section_name = Some { pelem ; _ } ;  section_items = { pelem = items ; _ };  _ }) ; _} ->
        begin
          match extract_url_checksum filename items with
          | Error `Msg msg, errs' -> csum_urls, `Msg ("extra-source " ^ pelem ^ " " ^ msg) :: errs' @ errs
          | Ok url, errs' -> url :: csum_urls, errs' @ errs
        end
      | _ -> csum_urls, errs)
    ([], []) opam.file_contents

let extract_urls filename str =
  (* in an opam file, there may be:
     url { src: <string> checksum: [ STRING ] } <- list of hash
     url { src: <string> checksum: STRING } <- single hash
     url { archive: <string> checksum: STRING } <- MD5
     extra-source NAME { src: URL checksum: [ STRING ] } (OR checksum: STRING) <- multiple occurences possible
  *)
  let open OpamParserTypes.FullPos in
  let opamfile = OpamParser.FullPos.string str filename in
  let unavailable =
    List.exists
      (function
        | { pelem = Variable ({ pelem = "available" ; _ },
                              { pelem = (Bool false | List { pelem = [{ pelem = Bool false; _ }] ; _ }); _ })
          ; _ } -> true
        | _ -> false)
      opamfile.file_contents
  in
  if unavailable then
     [], []
  else
    extract_checksums_and_urls filename opamfile
