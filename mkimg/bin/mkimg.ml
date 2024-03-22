(* I just made these ones up... *)
let tar_guid = Uuidm.of_string "53cd6812-46cc-474e-a141-30b3aed85f53" |> Option.get
let cache_guid = Uuidm.of_string "22ab9cf5-6e51-45c2-998a-862e23aab264" |> Option.get
let git_guid = Uuidm.of_string "30faa50a-4c9d-47ff-a1a5-ecfb3401c027" |> Option.get

(* GPT uses a 72 byte utf16be encoded string for partition names *)
let gptutf16be_of_ascii s =
  String.init 72
    (fun i ->
       if i mod 2 = 0 && i / 2 < String.length s then
         s.[i/2]
       else
         '\000')

let jump dest sector_size size_sectors sectors_cache sectors_git =
  let ( let* ) = Result.bind in
  let* () =
    if sector_size < 0 then Error "negative sector size"
    else if size_sectors < 0L then Error "negative size"
    else if sectors_cache < 0L then Error "negative cache size"
    else if sectors_git < 0L then Error "negative git dump size"
    else Ok ()
  in
  let* () =
    if sector_size >= 512 && sector_size land (pred sector_size) == 0 then
      Ok ()
    else Error "sector size must be a power of two greater than or equal 512"
  in
  (* ocaml-gpt uses a fixed size partition entries table. Create an empty GPT
     to figure out the first usable LBA *)
  let empty =
    Gpt.make ~sector_size ~disk_sectors:size_sectors []
    |> Result.get_ok
  in
  let* () =
    let ( + ) = Int64.add in
    if size_sectors <
       (* protective MBR + GPT header + GPT table *)
       empty.first_usable_lba +
       min 1L (Int64.of_int (2 * Tar.Header.length / sector_size)) + sectors_cache + sectors_cache + sectors_git
       + 1L (* backup GPT header *) then
      Error "too small size"
    else Ok ()
  in
  (* TODO: handle exceptions *)
  let fd = Unix.openfile dest Unix.[ O_WRONLY; O_CREAT ] 0o664 in
  Unix.ftruncate fd (sector_size * Int64.to_int size_sectors);
  let gpt =
    let partitions =
      (* Current implementation of [Gpt.Partition.make] only returns [Ok _] or
         raises [Invalid_argument _] :/ *)
      let attributes = 1L in
      let sha512s =
        Gpt.Partition.make
          ~name:(gptutf16be_of_ascii "sha512s")
          ~type_guid:cache_guid
          ~attributes
          Int64.(succ (sub empty.last_usable_lba sectors_cache))
          empty.last_usable_lba
        |> Result.get_ok
      in
      let md5s =
        Gpt.Partition.make
          ~name:(gptutf16be_of_ascii "md5s")
          ~type_guid:cache_guid
          ~attributes
          (Int64.sub sha512s.starting_lba sectors_cache)
          (Int64.pred sha512s.starting_lba)
        |> Result.get_ok
      in
      let git_dump =
        Gpt.Partition.make
          ~name:(gptutf16be_of_ascii "git_dump")
          ~type_guid:git_guid
          ~attributes
          (Int64.sub md5s.starting_lba sectors_git)
          (Int64.pred md5s.starting_lba)
        |> Result.get_ok
      in
      let tar =
        Gpt.Partition.make
          ~name:(gptutf16be_of_ascii "tar")
          ~type_guid:tar_guid
          ~attributes
          empty.first_usable_lba
          (Int64.pred git_dump.starting_lba)
        |> Result.get_ok
      in
      [ tar; git_dump; md5s; sha512s ]
    in
    Gpt.make ~sector_size ~disk_sectors:size_sectors partitions
    |> Result.get_ok
  in
  let buf =
    Cstruct.create (sector_size * (Int64.to_int gpt.first_usable_lba + 2 * Tar.Header.length))
  in
  Gptar.marshal_header ~sector_size buf gpt;
  Gpt.marshal_partition_table ~sector_size
    (Cstruct.shift buf (sector_size * Int64.to_int gpt.partition_entry_lba))
    gpt;
  let s = Cstruct.to_string buf in
  ignore (Unix.write_substring fd s 0 (String.length s));
  ignore (Unix.lseek fd (Int64.to_int gpt.backup_lba * sector_size) Unix.SEEK_SET);
  (* Let's reuse the buffer *)
  let buf = Cstruct.sub buf 0 sector_size in
  Cstruct.memset buf 0;
  Gpt.marshal_header ~sector_size ~primary:false buf gpt;
  let s = Cstruct.to_string buf in
  ignore (Unix.write_substring fd s 0 (String.length s));
  Unix.close fd;
  Ok ()

open Cmdliner

let dest =
  Arg.(required & pos 0 (some string) None &
       info ~docv:"DEST" [])

let sector_size =
  let doc = "Sector size or block size to use" in
  (* TODO: should be a power of two >= 512 *)
  Arg.(value & opt int 512 &
       info ~doc ~docv:"SECTOR-SIZE" ["sector-size"])

let size_sectors =
  let doc = "Size of disk image in terms of sectors" in
  Arg.(value & opt int64 (Int64.mul 1024L 2048L) &
       info ~doc ~docv:"SIZE-SECTORS" ["size-sectors"])

let sectors_cache =
  let doc = "Number of sectors reserved for each checksum cache (md5, sha512)." in
  Arg.(value & opt int64 (Int64.mul 4L 2048L) &
       info ~doc ~docv:"SECTORS-CACHE" ["sectors-cache"])

let sectors_git =
  let doc = "Number of sectors reserved for git dump." in
  Arg.(value & opt int64 (Int64.mul 40L 2048L) &
       info ~doc ~docv:"SECTORS-GIT" ["sectors-git"])

let command =
  let info =
    Cmd.info "mkimg"
  in
  Cmd.v info
    Term.(const jump $ dest $ sector_size $ size_sectors $ sectors_cache $ sectors_git)

let () =
  exit (Cmdliner.Cmd.eval_result command)
