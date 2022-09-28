let archives =
  let too_big =
    [ "https://github.com/Opsian/opsian-ocaml/releases/download/0.1/0.1.tar.gz" ]

  and hash_mismatch = [
    "http://cdn.skylable.com/source/libres3-1.3.tar.gz" ;
    "http://cdn.skylable.com/source/libres3-0.3.tar.gz" ;
    "http://cdn.skylable.com/source/libres3-1.2.tar.gz" ;
    "http://cdn.skylable.com/source/libres3-0.9.tar.gz" ;
    "http://cdn.skylable.com/source/libres3-0.2.tar.gz" ;
    "http://cdn.skylable.com/source/libres3-1.0.tar.gz" ;
    "http://cdn.skylable.com/source/libres3-1.1.tar.gz" ;
    "http://cdn.skylable.com/source/libres3-0.1.tar.gz" ;
    "https://github.com/lemaetech/http-cookie/releases/download/v3.0.0/http-cookie-v3.0.0.tbz" ;
    "http://oqamldebug.forge.ocamlcore.org/oqamldebug-0.9.4.tar.gz" ;
    "http://oqamldebug.forge.ocamlcore.org/oqamldebug-0.9.2.tar.gz" ;
    "http://oqamldebug.forge.ocamlcore.org/oqamldebug-0.9.3.tar.gz" ;
    "http://oqamldebug.forge.ocamlcore.org/oqamldebug-0.9.5.tar.gz" ;
    "http://oqamldebug.forge.ocamlcore.org/oqamldebug-0.9.1.tar.gz" ;
    "https://github.com/OCamlPro/ezjs_fetch/archive/0.1.tar.gz" ;
    "http://github.com/OCamlPro/typerex-build/archive/1.99.13-beta.tar.gz" ;
    "https://github.com/mirage/dyntype/tarball/dyntype-0.8.5" ;
    "https://github.com/mirage/dyntype/tarball/dyntype-0.8.3" ;
    "https://github.com/mirage/dyntype/tarball/dyntype-0.8.2" ;
    "https://github.com/mirage/dyntype/tarball/dyntype-0.8.4" ;
    "https://github.com/mirage/mirage-http-unix/archive/v1.0.0.tar.gz" ;
    "http://github.com/OCamlPro/typerex-build/archive/1.99.15-beta.tar.gz" ;
    "http://github.com/OCamlPro/typerex-build/archive/1.99.14-beta.tar.gz" ;
    "https://github.com/paulpatault/ocamlog/archive/v0.1.tar.gz" ;
    "https://github.com/pveber/OCaml-R/archive/pre-nyc-refactoring.tar.gz" ;
    "https://github.com/paulpatault/ocamlog/archive/v0.2.tar.gz" ;
    "http://github.com/OCamlPro/typerex-build/archive/1.99.16-beta.tar.gz" ;
    "https://github.com/FStarLang/kremlin/archive/v0.9.6.0.zip" ;
    "https://gitlab.com/dailambda/plebeia/-/archive/2.0.2/plebeia-2.0.2.tar.gz" ;
    "https://github.com/mirleft/ocaml-tls/archive/0.5.0.tar.gz" ;
    "https://github.com/eth-sri/ELINA/archive/1.3.tar.gz" ;
    "https://gitlab.com/trustworthy-refactoring/refactorer/-/archive/0.1/refactorer-0.1.zip" ;
    "https://github.com/completium/archetype-lang/archive/1.3.3.tar.gz" ;
    "https://github.com/chetmurthy/pa_ppx/archive/0.01.tar.gz" ;
    "https://github.com/chambart/ocaml-1/archive/lto.tar.gz" ;
    "https://github.com/Kappa-Dev/KaSim/archive/v3.5-250915.tar.gz" ;
    "https://github.com/bsansouci/bsb-native/archive/1.9.4.tar.gz"
  ]

  and bad_request = [
    "http://cgit.freedesktop.org/cairo-ocaml/snapshot/cairo-ocaml-1.2.0.tar.gz"
  ]

  and not_found = [
    "http://pw374.github.io/distrib/frag/frag-0.1.0.tar.gz" ;
    "http://pw374.github.io/distrib/glical/glical-0.0.3.tar.gz" ;
    "http://pw374.github.io/distrib/glical/glical-0.0.4.tar.gz" ;
    "http://pw374.github.io/distrib/glical/glical-0.0.1.tar.gz" ;
    "http://pw374.github.io/distrib/glical/glical-0.0.2.tar.gz" ;
    "http://pw374.github.io/distrib/glical/glical-0.0.5.tar.gz" ;
    "http://pw374.github.io/distrib/glical/glical-0.0.7.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.1.1.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.1.0.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.1.2.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.1.7.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.1.3.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.1.8.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.1.4.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.1.5.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.2.0.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.2.1.tar.gz" ;
    "http://pw374.github.io/distrib/mpp/mpp-0.3.0.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.3.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.4.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.5.4.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.5.5.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.5.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.6.0.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.6.2.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.6.3.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.6.4.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.6.5.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.7.0.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.7.1.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.7.2.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.7.4.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.7.3.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.7.5.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.8.2.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.8.0.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.8.1.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.9.0.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.9.1.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.9.7.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.0.0.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.0.1.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.1.0.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.1.1.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.1.2.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.2.0.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.2.1.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.2.2.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.2.4.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.2.5.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.2.6.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.2.3.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.3.0.tar.gz" ;
    "http://zoggy.github.com/ocamldot/ocamldot-1.0.tar.gz" ;
    "http://zoggy.github.io/stog/stog-0.4.tar.gz" ;
    "http://zoggy.github.io/genet/genet-0.6.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.6.1.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.9.4.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.9.6.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.9.5.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-0.9.3.tar.gz" ;
    "http://pw374.github.io/distrib/omd/omd-1.1.3.tar.gz" ;
    "http://coccinelle.lip6.fr/distrib/coccinelle-1.0.0-rc22.tgz" ;
    "http://coccinelle.lip6.fr/distrib/coccinelle-1.0.0-rc21.tgz" ;
    "http://coccinelle.lip6.fr/distrib/coccinelle-1.0.0.tgz" ;
    "http://proverif.inria.fr/proverif1.96pl1.tar.gz" ;
    "http://proverif.inria.fr/proverif1.97.tar.gz" ;
    "http://proverif.inria.fr/proverif1.98.tar.gz" ;
    "http://proverif.inria.fr/proverif1.97pl3.tar.gz" ;
    "http://proverif.inria.fr/proverif1.98pl1.tar.gz" ;
    "http://proverif.inria.fr/proverif1.97pl1.tar.gz" ;
    "https://github.com/jrochel/eliom/archive/6.4.0.tar.gz" ;
    "https://github.com/drjdn/ocaml_lua_parser/archive/1.0.1.tar.gz" ;
    "https://github.com/sagotch/To.ml/archive/v1.0.0.tar.gz" ;
    "https://zoggy.github.io/ocaml-rdf/ocaml-rdf-0.9.0.tar.gz" ;
    "https://github.com/sagotch/To.ml/archive/v2.1.0.tar.gz" ;
    "https://github.com/sagotch/To.ml/archive/v2.0.0.tar.gz" ;
    "https://zoggy.github.io/ocaml-taglog/taglog-0.1.0.tar.gz" ;
    "https://zoggy.github.io/ocaml-taglog/taglog-0.2.0.tar.gz" ;
    "https://zoggy.github.io/ocf/ocf-0.3.0.tar.gz" ;
    "https://zoggy.github.io/ojs-base/ojs-base-0.1.0.tar.gz" ;
    "https://zoggy.github.io/stog/plugins/stog-writing-0.8.0.tar.gz" ;
    "https://zoggy.github.io/stog/stog-0.13.0.tar.gz" ;
    "https://zoggy.github.io/ocaml-taglog/taglog-0.3.0.tar.gz" ;
    "https://zoggy.github.io/ocf/ocf-0.1.0.tar.gz" ;
    "https://opam.ocaml.org/cache/md5/24/24b163eb77e6832747dccd6cc8a5d57c" ;
  ]

  and forbidden = [
    "https://gforge.inria.fr/frs/download.php/33440/heptagon-1.00.06.tar.gz" ;
    "https://gforge.inria.fr/frs/download.php/file/33677/dose3-3.2.2.tar.gz" ;
    "https://gforge.inria.fr/frs/download.php/file/34920/javalib-2.3.1.tar.bz2" ;
    "https://gforge.inria.fr/frs/download.php/file/36092/javalib-2.3.2.tar.bz2" ;
    "https://gforge.inria.fr/frs/download.php/file/36093/sawja-1.5.2.tar.bz2" ;
    "https://gforge.inria.fr/frs/download.php/file/37154/javalib-2.3.4.tar.bz2" ;
    "https://gforge.inria.fr/frs/download.php/file/37403/sawja-1.5.3.tar.bz2" ;
    "https://gforge.inria.fr/frs/download.php/file/36307/javalib-2.3.3.tar.bz2" ;
    "https://gforge.inria.fr/frs/download.php/file/37655/javalib-2.3.5.tar.bz2" ;
    "https://gforge.inria.fr/frs/download.php/file/37656/sawja-1.5.4.tar.bz2" ;
    "https://gforge.inria.fr/frs/download.php/file/34921/sawja-1.5.1.tar.bz2" ;
  ]

  and three_o_o = [
    "https://github.com/Gbury/dolmen/archive/v0.4.tar.gz" ;
    "https://github.com/Stevendeo/Pilat/archive/1.3.tar.gz" ;
    "https://github.com/OCamlPro/ocp-indent/archive/1.5.tar.gz" ;
    "https://github.com/backtracking/combine/archive/release-0.6.zip" ;
    "https://github.com/cakeplus/pa_comprehension/archive/0.4.tar.gz" ;
    "https://github.com/cakeplus/mparser/archive/1.0.tar.gz" ;
    "https://github.com/chenyukang/rubytt/archive/v0.1.tar.gz" ;
    "https://github.com/cakeplus/pa_where/archive/0.4.tar.gz" ;
    "https://github.com/metaocaml/ber-metaocaml/archive/ber-n102.tar.gz" ;
    "https://github.com/cakeplus/pa_solution/archive/0.5.tar.gz" ;
    "https://github.com/cakeplus/mparser/archive/1.2.1.tar.gz" ;
    "https://github.com/cakeplus/pa_solution/archive/0.7.tar.gz" ;
    "https://github.com/cakeplus/pa_solution/archive/0.6.tar.gz" ;
    "https://github.com/mirage/mirage-tcpip/archive/v2.8.1.tar.gz" ;
    "https://github.com/modlfo/pla/archive/v1.4.tar.gz" ;
    "https://github.com/murmour/pa_qualified/archive/0.5.tar.gz" ;
    "https://github.com/ocaml-ppx/ocamlformat/archive/v0.2.tar.gz" ;
    "https://github.com/murmour/pa_qualified/archive/0.6.tar.gz" ;
    "https://github.com/ocaml-ppx/ocamlformat/archive/support.0.2.tar.gz" ;
    "https://github.com/ocaml/oloop/archive/0.1.2.tar.gz" ;
    "https://github.com/cakeplus/mparser/archive/1.0.1.tar.gz" ;
    "https://github.com/cakeplus/mparser/archive/1.1.tar.gz" ;
    "https://github.com/savonet/ocaml-ffmpeg/archive/v1.0.0-rc1.tar.gz" ;
    "https://github.com/ocaml/opam2web/archive/2.0.tar.gz" ;
    "https://github.com/savonet/ocaml-ffmpeg/archive/v1.0.0.tar.gz" ;
  ]

  and five_o_three = [ "https://gitlab.com/gasche/build_path_prefix_map/repository/0.2/archive.tar.gz" ]

  and is_ftp = [ "ftp://ftp.netbsd.org/pub/pkgsrc/distfiles/wyrd-1.4.6.tar.gz" ]

  and connect_fails = [
    "http://godi.0ok.org/godi-backup/shcaml-0.1.3.tar.gz" ;
    "http://www.first.in-berlin.de/software/tools/apalogretrieve/apalogretrieve-0-9-6_4.tgz" ;
    "https://cavale.enseeiht.fr/osdp/osdp-0.5.4.tgz" ;
    "https://cavale.enseeiht.fr/osdp/osdp-0.6.0.tgz" ;
    "https://cavale.enseeiht.fr/osdp/osdp-1.0.0.tgz" ;
  ]
  in

  too_big @ hash_mismatch @ bad_request @ not_found @ forbidden @ three_o_o @ five_o_three @ is_ftp @ connect_fails
