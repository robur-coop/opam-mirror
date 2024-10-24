let src = Logs.Src.create "opam-file.opam-mirror" ~doc:"Opam file decoding in opam-mirror"
module Log = (val Logs.src_log src : Logs.LOG)

module HM = Archive_checksum.HM

let hash_to_string = Archive_checksum.Hash.to_string

let hex_of_string s =
  match Ohex.decode s with
  | d -> Ok d
  | exception Invalid_argument err -> Error (`Msg err)

let decode_digest filename str =
  let hex h s =
    match hex_of_string s with
    | Ok d -> Some (h, d)
    | Error `Msg msg ->
      Log.warn (fun m -> m "%s invalid hex (%s) %s" filename msg s); None
  in
  match String.split_on_char '=' str with
  | [ data ] -> hex `MD5 data
  | [ "md5" ; data ] -> hex `MD5 data
  | [ "sha256" ; data ] -> hex `SHA256 data
  | [ "sha512" ; data ] -> hex `SHA512 data
  | [ hash ; _ ] -> Log.warn (fun m -> m "%s unknown hash %s" filename hash); None
  | _ -> Log.warn (fun m -> m "%s unexpected hash format %S" filename str); None

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
  in
  let url =
    match url, archive with
    | Some { pelem = Variable (_, { pelem = String url ; _ }) ; _ }, None -> Some url
    | None, Some { pelem = Variable (_, { pelem = String url ; _ }); _ } -> Some url
    | _ ->
      Log.warn (fun m -> m "%s neither src nor archive present" filename); None
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
                        Log.warn (fun m -> m "for %s, hash %s, multiple keys are present: %s %s"
                                     (Option.value ~default:"NONE" url) (hash_to_string h) (Ohex.encode v) (Ohex.encode v'));
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
      Log.warn (fun m -> m "couldn't decode checksum in %s" filename);
      None
  in
  match url, csum with
  | Some url, Some cs -> Some (url, cs)
  | _ -> None

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
    (Log.debug (fun m -> m "%s is marked unavailable, skipping" filename);
     None)
  else
    match
      List.find_opt (function
          | { pelem = Section ({ section_kind = { pelem = "url" ; _ } ; _ }) ; _} -> true | _ -> false)
        opamfile.file_contents
    with
    | Some { pelem = Section ({ section_items = { pelem = items ; _ }; _}) ; _ } ->
      extract_url_checksum filename items
    | _ -> Log.debug (fun m -> m "no url section for %s" filename); None
