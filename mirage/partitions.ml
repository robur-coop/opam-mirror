open Lwt.Syntax

module Make(BLOCK : Mirage_block.S) = struct
  module Part = Mirage_block_partition.Make(BLOCK)

  include Part

  type partitions = {
    tar : Part.t ;
    git_dump : Part.t ;
    md5s : Part.t ;
    sha512s : Part.t ;
  }

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
    let utf16be_of_ascii s =
      String.init 72
        (fun i ->
           if i mod 2 = 0 && i / 2 < String.length s then
             s.[i/2]
           else
             '\000')
    in
    let* info = BLOCK.get_info block in
    let* gpt = read_partition_table info block in
    let tar, git_dump, md5s, sha512s =
      match
        List.fold_left
          (fun (tar, git_dump, md5s, sha512s) p ->
             if String.equal p.Gpt.Partition.name
                 (utf16be_of_ascii "tar")
             then
               (Some p, git_dump, md5s, sha512s)
             else if String.equal p.name
                 (utf16be_of_ascii "git_dump")
             then
               (tar, Some p, md5s, sha512s)
             else if String.equal p.name
                 (utf16be_of_ascii "md5s")
             then
               (tar, git_dump, Some p, sha512s)
             else if String.equal p.name
                 (utf16be_of_ascii "sha512s")
             then
               (tar, git_dump, md5s, Some p)
             else
               Format.kasprintf failwith "Unknown partition %S" p.name)
          (None, None, None, None)
          gpt.partitions
      with
      | (Some tar, Some git_dump, Some md5s, Some sha512s) ->
        (tar, git_dump, md5s, sha512s)
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
    let tar = get_part tar and git_dump = get_part git_dump
    and md5s = get_part md5s and sha512s = get_part sha512s in
    { tar ; git_dump ; md5s ; sha512s }
end
