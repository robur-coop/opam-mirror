

module Hash = struct
  type t = [ `MD5 | `SHA1 | `SHA224 | `SHA256 | `SHA384 | `SHA512 ]

  (* Make the compiler check that (t :> Digestif.hash') *)
  let _ = fun (h :t) -> (h :> Digestif.hash')

  let compare h h' =
    match h, h' with
    | `SHA512, `SHA512 -> 0
    | `SHA512, _ -> 1
    | _, `SHA512 -> -1
    | `SHA384, `SHA384 -> 0
    | `SHA384, _ -> 1
    | _, `SHA384 -> -1
    | `SHA256, `SHA256 -> 0
    | `SHA256, _ -> 1
    | _, `SHA256 -> -1
    | `SHA224, `SHA224 -> 0
    | `SHA224, _ -> 1
    | _, `SHA224 -> -1
    | `SHA1, `SHA1 -> 0
    | `SHA1, `MD5 -> 1
    | `MD5, `MD5 -> 0
    | `MD5, _ -> -1

  let to_string = function
    | `MD5 -> "md5"
    | `SHA1 -> "sha1"
    | `SHA224 -> "sha224"
    | `SHA256 -> "sha256"
    | `SHA384 -> "sha384"
    | `SHA512 -> "sha512"

  let of_string = function
    | "md5" -> Ok `MD5
    | "sha256" -> Ok `SHA256
    | "sha512" -> Ok `SHA512
    | h -> Error (`Msg ("unknown hash algorithm: " ^ h))
end

module HM = Map.Make(Hash)

module Running_hash = struct
  type _ t =
    | MD5 : Digestif.MD5.ctx -> [> `MD5 ] t
    | SHA1 : Digestif.SHA1.ctx -> [> `SHA1 ] t
    | SHA224 : Digestif.SHA224.ctx -> [> `SHA224 ] t
    | SHA256 : Digestif.SHA256.ctx -> [> `SHA256 ] t
    | SHA384 : Digestif.SHA384.ctx -> [> `SHA384 ] t
    | SHA512 : Digestif.SHA512.ctx -> [> `SHA512 ] t

  let empty : _ -> _ t = function
    | `MD5 -> MD5 Digestif.MD5.empty
    | `SHA1 -> SHA1 Digestif.SHA1.empty
    | `SHA224 -> SHA224 Digestif.SHA224.empty
    | `SHA256 -> SHA256 Digestif.SHA256.empty
    | `SHA384 -> SHA384 Digestif.SHA384.empty
    | `SHA512 -> SHA512 Digestif.SHA512.empty

  let feed_string t data =
    match t with
    | MD5 t -> MD5 (Digestif.MD5.feed_string t data)
    | SHA1 t -> SHA1 (Digestif.SHA1.feed_string t data)
    | SHA224 t -> SHA224 (Digestif.SHA224.feed_string t data)
    | SHA256 t -> SHA256 (Digestif.SHA256.feed_string t data)
    | SHA384 t -> SHA384 (Digestif.SHA384.feed_string t data)
    | SHA512 t -> SHA512 (Digestif.SHA512.feed_string t data)

  let get t =
    match t with
    | MD5 t -> Digestif.MD5.(to_raw_string (get t))
    | SHA1 t -> Digestif.SHA1.(to_raw_string (get t))
    | SHA224 t -> Digestif.SHA224.(to_raw_string (get t))
    | SHA256 t -> Digestif.SHA256.(to_raw_string (get t))
    | SHA384 t -> Digestif.SHA384.(to_raw_string (get t))
    | SHA512 t -> Digestif.SHA512.(to_raw_string (get t))

  let hash_alg t =
    match t with
    | MD5 _ -> `MD5
    | SHA1 _ -> `SHA1
    | SHA224 _ -> `SHA224
    | SHA256 _ -> `SHA256
    | SHA384 _ -> `SHA384
    | SHA512 _ -> `SHA512
end

type 'a digests = {
  md5 : Digestif.MD5.ctx;
  sha256 : Digestif.SHA256.ctx;
  sha512 : Digestif.SHA512.ctx;
  csum : 'a Running_hash.t;
}

let empty_digests h =
  let csum = Running_hash.empty h in
  {
    md5 = Digestif.MD5.empty;
    sha256 = Digestif.SHA256.empty;
    sha512 = Digestif.SHA512.empty;
    csum;
  }

let update_digests { md5; sha256; sha512; csum } data =
  {
    md5 = Digestif.MD5.feed_string md5 data;
    sha256 = Digestif.SHA256.feed_string sha256 data;
    sha512 = Digestif.SHA512.feed_string sha512 data;
    csum = Running_hash.feed_string csum data;
  }

let init_write csums =
  let hash, csum = HM.max_binding csums in
  (hash, csum), Ok (empty_digests hash, `Init)

let digests_to_hm digests =
  HM.empty
  |> HM.add `MD5
    Digestif.MD5.(to_raw_string (get digests.md5))
  |> HM.add `SHA256
    Digestif.SHA256.(to_raw_string (get digests.sha256))
  |> HM.add `SHA512
    Digestif.SHA512.(to_raw_string (get digests.sha512))
  |> HM.add (Running_hash.hash_alg digests.csum)
    (Running_hash.get digests.csum)
