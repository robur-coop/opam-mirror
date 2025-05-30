open Lwt.Syntax

module Make(BLOCK : Mirage_block.S) = struct
  module Part = Mirage_block_partition.Make(BLOCK)

  include Part

  type partitions = {
    tar : Part.t ;
    swap : Part.t ;
    index : Part.t ;
    git_dump : Part.t ;
    md5s : Part.t ;
    sha512s : Part.t ;
  }

  (* I just made these ones up... *)
  let swap_guid = Uuidm.of_string "76515dc1-953f-4c59-8b41-90011bdddfcd" |> Option.get
  let tar_guid = Uuidm.of_string "53cd6812-46cc-474e-a141-30b3aed85f53" |> Option.get
  let cache_guid = Uuidm.of_string "22ab9cf5-6e51-45c2-998a-862e23aab264" |> Option.get
  let git_guid = Uuidm.of_string "30faa50a-4c9d-47ff-a1a5-ecfb3401c027" |> Option.get
  let index_guid = Uuidm.of_string "1cf8c2dc-a7fd-11ef-a2a6-68f728e7bbbc" |> Option.get

  (* GPT uses a 72 byte utf16be encoded string for partition names *)
  let utf16be_of_ascii s =
    String.init 72
      (fun i ->
         if i mod 2 = 0 && i / 2 < String.length s then
           s.[i/2]
         else
           '\000')

  let read_partition_table info block =
    let b = Cstruct.create info.Mirage_block.sector_size in
    (* We will ignore the protective MBR at lba [0L] *)
    let* r = BLOCK.read block 1L [b] in
    match r with
    | Error e ->
      Format.kasprintf failwith "Reading partition table: %a"
        BLOCK.pp_error e
    | Ok () ->
      match Gpt.unmarshal b ~sector_size:info.Mirage_block.sector_size with
      | Error e ->
        Format.kasprintf failwith "Reading partition table: %s" e
      | Ok (`Read_partition_table (lba, sectors), k) ->
        let b = Cstruct.create (sectors * info.Mirage_block.sector_size) in
        let* r = BLOCK.read block lba [b] in
        match r with
        | Error e ->
          Format.kasprintf failwith "Reading partition table: %a"
            BLOCK.pp_error e
        | Ok () ->
          match k b with
          | Error e ->
            Format.kasprintf failwith "Reading partition table: %s" e
          | Ok gpt -> Lwt.return gpt

  let connect block =
    let* info = BLOCK.get_info block in
    let* gpt = read_partition_table info block in
    let tar, swap, index, git_dump, md5s, sha512s =
      match
        List.fold_left
          (fun (tar, swap, index, git_dump, md5s, sha512s) p ->
             if String.equal p.Gpt.Partition.name
                 (utf16be_of_ascii "tar")
             then
               (Some p, swap, index, git_dump, md5s, sha512s)
             else if String.equal p.name
                 (utf16be_of_ascii "git_dump")
             then
               (tar, swap, index, Some p, md5s, sha512s)
             else if String.equal p.name
                 (utf16be_of_ascii "md5s")
             then
               (tar, swap, index, git_dump, Some p, sha512s)
             else if String.equal p.name
                 (utf16be_of_ascii "sha512s")
             then
               (tar, swap, index, git_dump, md5s, Some p)
             else if String.equal p.name
                 (utf16be_of_ascii "swap")
             then
               (tar, Some p, index, git_dump, md5s, sha512s)
             else if String.equal p.name
                 (utf16be_of_ascii "index")
             then
               (tar, swap, Some p, git_dump, md5s, sha512s)
             else
               Format.kasprintf failwith "Unknown partition %S" p.name)
          (None, None, None, None, None, None)
          gpt.partitions
      with
      | (Some tar, Some swap, Some index, Some git_dump, Some md5s, Some sha512s) ->
        (tar, swap, index, git_dump, md5s, sha512s)
      | _ ->
        failwith "not all partitions found :("
    in
    let+ (_empty, p) = Part.connect 0L block in
    let get_part part =
      let len = Int64.(succ (sub part.Gpt.Partition.ending_lba part.starting_lba)) in
      let (_before, after) = Part.subpartition part.starting_lba p in
      let (part, _after) = Part.subpartition len after in
      part
    in
    let tar = get_part tar and swap = get_part swap and index = get_part index
    and git_dump = get_part git_dump
    and md5s = get_part md5s and sha512s = get_part sha512s in
    { tar ; swap; index ; git_dump ; md5s ; sha512s }

  let format block ~cache_size ~git_size ~swap_size ~index_size =
    let* { size_sectors; sector_size; _ } = BLOCK.get_info block in
    let ( let*? ) = Lwt_result.bind in
    (* ocaml-gpt uses a fixed size partition entries table. Create an empty GPT
       to figure out the first usable LBA *)
    let empty =
      Gpt.make ~sector_size ~disk_sectors:size_sectors []
      |> Result.get_ok
    in
    let mb_in_sectors mb =
      (* 1 megabyte is 2^20 bytes (1024 * 1024) *)
      let mb_in_bytes = Int64.(shift_left (of_int mb) 20) in
      let ss = Int64.of_int sector_size in
      Int64.(div (add mb_in_bytes (sub ss 1L)) ss)
    in
    let sectors_cache = mb_in_sectors cache_size
    and sectors_git = mb_in_sectors git_size
    and sectors_swap = mb_in_sectors swap_size
    and sectors_index = mb_in_sectors index_size
    in
    let*? () =
      if size_sectors <
         (* protective MBR + GPT header + GPT table *)
         let ( + ) = Int64.add in
         empty.first_usable_lba +
         min 1L (Int64.of_int (2 * Tar.Header.length / sector_size)) + sectors_cache + sectors_cache + sectors_git + sectors_index
         + 1L (* backup GPT header *) then
        Lwt.return_error (`Msg "too small disk")
      else Lwt_result.return ()
    in
    (* Current implementation of [Gpt.Partition.make] only returns [Ok _] or
       raises [Invalid_argument _] :/ *)
    let attributes = 1L in
    let sha512s =
      Gpt.Partition.make
        ~name:(utf16be_of_ascii "sha512s")
        ~type_guid:cache_guid
        ~attributes
        Int64.(succ (sub empty.last_usable_lba sectors_cache))
        empty.last_usable_lba
      |> Result.get_ok
    in
    let md5s =
      Gpt.Partition.make
        ~name:(utf16be_of_ascii "md5s")
        ~type_guid:cache_guid
        ~attributes
        (Int64.sub sha512s.starting_lba sectors_cache)
        (Int64.pred sha512s.starting_lba)
      |> Result.get_ok
    in
    let git_dump =
      Gpt.Partition.make
        ~name:(utf16be_of_ascii "git_dump")
        ~type_guid:git_guid
        ~attributes
        (Int64.sub md5s.starting_lba sectors_git)
        (Int64.pred md5s.starting_lba)
      |> Result.get_ok
    in
    let index =
      Gpt.Partition.make
        ~name:(utf16be_of_ascii "index")
        ~type_guid:index_guid
        ~attributes
        (Int64.sub git_dump.starting_lba sectors_index)
        (Int64.pred git_dump.starting_lba)
      |> Result.get_ok
    in
    let swap =
      Gpt.Partition.make
        ~name:(utf16be_of_ascii "swap")
        ~type_guid:swap_guid
        ~attributes
        (Int64.sub index.starting_lba sectors_swap)
        (Int64.pred index.starting_lba)
      |> Result.get_ok
    in
    let tar =
      Gpt.Partition.make
        ~name:(utf16be_of_ascii "tar")
        ~type_guid:tar_guid
        ~attributes
        empty.first_usable_lba
        (Int64.pred swap.starting_lba)
      |> Result.get_ok
    in
    let gpt =
      let partitions =
        [ tar; swap; index; git_dump; md5s; sha512s ]
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
    let write block sector_start buffers =
      BLOCK.write block sector_start buffers
      |> Lwt_result.map_error (fun e -> `Block e)
    in
    let*? () =
      write block 0L [ buf ]
    in
    (* Format the file systems by writing zeroes *)
    (* For tar we need to zero (at least) the first 2*512 bytes so we round up
       to the nearest sector alignment *)
    let zeroes =
      let sectors =
        (2 * Tar.Header.length + sector_size - 1) / sector_size * sector_size
      in
      Cstruct.create sectors in
    let*? () =
      write block tar.starting_lba [ zeroes ]
    in
    (* For the OneFFS filesystems we just need to zero out the first sector *)
    let zero_sector = Cstruct.create sector_size in
    let*? () =
      write block git_dump.starting_lba [ zero_sector ]
    in
    let*? () =
      write block md5s.starting_lba [ zero_sector ]
    in
    let*? () =
      write block sha512s.starting_lba [ zero_sector ]
    in
    write block index.starting_lba [ zero_sector ]
end
