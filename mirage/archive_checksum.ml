

module Hash = struct
  type t = (* OpamHash.kind = *) [ `MD5 | `SHA256 | `SHA512 ]

  (* Make the compiler check that (t :> Digestif.hash') *)
  let _ = fun (h :t) -> (h :> Digestif.hash')

  let compare h h' =
    match h, h' with
    | `SHA512, `SHA512 -> 0
    | `SHA512, _ -> 1
    | _, `SHA512 -> -1
    | `SHA256, `SHA256 -> 0
    | `SHA256, _ -> 1
    | _, `SHA256 -> -1
    | `MD5, `MD5 -> 0

  let to_string = function
    | `MD5 -> "md5"
    | `SHA256 -> "sha256"
    | `SHA512 -> "sha512"

  let of_string = function
    | "md5" -> Ok `MD5
    | "sha256" -> Ok `SHA256
    | "sha512" -> Ok `SHA512
    | h -> Error (`Msg ("unknown hash algorithm: " ^ h))
end

module HM = Map.Make(Hash)

type 'a digests = {
  md5 : Digestif.MD5.ctx;
  sha256 : Digestif.SHA256.ctx;
  sha512 : Digestif.SHA512.ctx;
}

let empty_digests =
  {
    md5 = Digestif.MD5.empty;
    sha256 = Digestif.SHA256.empty;
    sha512 = Digestif.SHA512.empty;
  }

let update_digests { md5; sha256; sha512 } data =
  {
    md5 = Digestif.MD5.feed_string md5 data;
    sha256 = Digestif.SHA256.feed_string sha256 data;
    sha512 = Digestif.SHA512.feed_string sha512 data;
  }

let init_write csums =
  let hash, csum = HM.max_binding csums in
  (hash, csum), empty_digests

let digests_to_hm digests =
  HM.empty
  |> HM.add `MD5
    Digestif.MD5.(to_raw_string (get digests.md5))
  |> HM.add `SHA256
    Digestif.SHA256.(to_raw_string (get digests.sha256))
  |> HM.add `SHA512
    Digestif.SHA512.(to_raw_string (get digests.sha512))

let get digests = function
  | `MD5 -> Digestif.MD5.(to_raw_string (get digests.md5))
  | `SHA256 -> Digestif.SHA256.(to_raw_string (get digests.sha256))
  | `SHA512 -> Digestif.SHA512.(to_raw_string (get digests.sha512))
