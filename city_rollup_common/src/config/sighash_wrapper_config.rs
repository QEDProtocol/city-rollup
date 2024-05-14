use city_crypto::hash::qhashout::QHashOut;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};

type F = GoldilocksField;
pub const SIGHASH_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 16;
pub const SIGHASH_CIRCUIT_MAX_WITHDRAWALS: usize = 2;
pub const SIGHASH_CIRCUIT_MAX_DEPOSITS: usize = 2;
pub const SIGHASH_WHITELIST_TREE_ROOT: QHashOut<F> = QHashOut(HashOut {
    elements: [
        GoldilocksField(9859455400695850694),
        GoldilocksField(6786059973533892138),
        GoldilocksField(3058489071444420670),
        GoldilocksField(12047212035328261685),
    ],
});

pub const SIGHASH_CIRCUIT_FINGERPRINTS: [QHashOut<F>; 162] = [
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18009610824973321195),
            GoldilocksField(5871292423068658710),
            GoldilocksField(3550874203583647012),
            GoldilocksField(9370313751164330101),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17219933315275076211),
            GoldilocksField(14308811520181220296),
            GoldilocksField(2688168398681955543),
            GoldilocksField(12292852866085410364),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4095941922967154948),
            GoldilocksField(13035613321748620733),
            GoldilocksField(3450646596630593219),
            GoldilocksField(3219405227189685352),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9002004987070417564),
            GoldilocksField(4560400876482804370),
            GoldilocksField(2316881801532523730),
            GoldilocksField(8210502537412350240),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1119364605524575497),
            GoldilocksField(1050257230786663948),
            GoldilocksField(16346090470143778903),
            GoldilocksField(14863564570867670270),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15981907335420109915),
            GoldilocksField(5989582848396429079),
            GoldilocksField(17067628847271463973),
            GoldilocksField(16401326003534960553),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6180457628850797604),
            GoldilocksField(4895960178279247152),
            GoldilocksField(11983059715440314579),
            GoldilocksField(12203000486076295486),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10296976133192999602),
            GoldilocksField(9047626975292514834),
            GoldilocksField(3390322098899039251),
            GoldilocksField(14469952556926793484),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18124800220992369943),
            GoldilocksField(17589654945960350158),
            GoldilocksField(7485040295449694402),
            GoldilocksField(2420746865304055344),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1455218666320925009),
            GoldilocksField(7006960694846164957),
            GoldilocksField(6131281135135276263),
            GoldilocksField(6226396540127330876),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5980613161473468627),
            GoldilocksField(15796155277466274813),
            GoldilocksField(744035018890507461),
            GoldilocksField(9106183510748446925),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16476577155539832569),
            GoldilocksField(11428022808863905967),
            GoldilocksField(13826841381815271403),
            GoldilocksField(7154586389591791958),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14597661106046441167),
            GoldilocksField(14344320355696838169),
            GoldilocksField(7512259949193058279),
            GoldilocksField(15143753879150601170),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14314689716931559433),
            GoldilocksField(13855306204668265558),
            GoldilocksField(17176650129704104087),
            GoldilocksField(13752935307177275299),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9559895030801394128),
            GoldilocksField(2467251673487654820),
            GoldilocksField(6977610561187882870),
            GoldilocksField(9113561509364920020),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6734769779543949585),
            GoldilocksField(9229554548313644080),
            GoldilocksField(10390219822142101869),
            GoldilocksField(5378800345694843559),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11987006339381496509),
            GoldilocksField(15663898462846457356),
            GoldilocksField(10326836188059989844),
            GoldilocksField(7810153403527159198),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5057253656367599369),
            GoldilocksField(12525747636344281211),
            GoldilocksField(13121830192268149932),
            GoldilocksField(10110796444186857159),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(394768059204867981),
            GoldilocksField(13240432927092129491),
            GoldilocksField(14576771370487460112),
            GoldilocksField(6992519717079502988),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8361940053991069494),
            GoldilocksField(14448982876207570687),
            GoldilocksField(16896366247561624383),
            GoldilocksField(15724080838593616997),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12122558346695603159),
            GoldilocksField(17065172247705347511),
            GoldilocksField(7530804196809942762),
            GoldilocksField(3140049088467807070),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11187701170893071109),
            GoldilocksField(2984987430707287015),
            GoldilocksField(15846632349520501835),
            GoldilocksField(1707846446679961665),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7469439929758130070),
            GoldilocksField(4600752635667986556),
            GoldilocksField(16091703681790715130),
            GoldilocksField(6953167017594586186),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2397135925071128715),
            GoldilocksField(13105153458289848198),
            GoldilocksField(2968622972190910041),
            GoldilocksField(16901566411204611170),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11833727343501271945),
            GoldilocksField(4122863538028882931),
            GoldilocksField(16401912660074793893),
            GoldilocksField(130534673109109598),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8972507377277310724),
            GoldilocksField(9303898830884539531),
            GoldilocksField(2644084712026214518),
            GoldilocksField(7595820413620383596),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12343198179441327198),
            GoldilocksField(7387825071618782354),
            GoldilocksField(1387189752001910678),
            GoldilocksField(16435474321813389942),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(237675165301078836),
            GoldilocksField(16010583565068518329),
            GoldilocksField(3555513072308780464),
            GoldilocksField(16796057011767732651),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9981297854704373060),
            GoldilocksField(14468920568020346625),
            GoldilocksField(8010237695408690461),
            GoldilocksField(3970871482709334082),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7911526354192163618),
            GoldilocksField(10066218967981393141),
            GoldilocksField(6209062242800247927),
            GoldilocksField(14840970668852478359),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1916402890182853399),
            GoldilocksField(153645349448816601),
            GoldilocksField(14359735901666230797),
            GoldilocksField(10694755107170380890),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5009331062567722609),
            GoldilocksField(7816801984560461291),
            GoldilocksField(15128711205323623768),
            GoldilocksField(17920824230598402663),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1267716251124137387),
            GoldilocksField(2223986665059557657),
            GoldilocksField(12692874043573464946),
            GoldilocksField(8438928506056774911),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3528475006927247242),
            GoldilocksField(10736419931770156899),
            GoldilocksField(2776637433575689130),
            GoldilocksField(13137429152987343576),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16942447884268140214),
            GoldilocksField(11953694911083215529),
            GoldilocksField(14403127497291298525),
            GoldilocksField(5913760674270559777),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11668153139748984277),
            GoldilocksField(9608392903049067960),
            GoldilocksField(7782617429390060366),
            GoldilocksField(6050969484545596817),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1607333887784604798),
            GoldilocksField(10790796289684623846),
            GoldilocksField(6932279554259652016),
            GoldilocksField(1897672287585400886),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3999863906561202444),
            GoldilocksField(3060977224371812371),
            GoldilocksField(8755663211756773938),
            GoldilocksField(7642023893032228388),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13150578640030705859),
            GoldilocksField(1182421346949888513),
            GoldilocksField(3657352240666216425),
            GoldilocksField(1154745455890698244),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14295103819576461834),
            GoldilocksField(10576249843856801300),
            GoldilocksField(8186769007818794151),
            GoldilocksField(12405650908876666524),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10824640654568035868),
            GoldilocksField(14459969159672461523),
            GoldilocksField(4492185934235945797),
            GoldilocksField(11445581789737429303),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1784035665505380921),
            GoldilocksField(8321926640263826597),
            GoldilocksField(8032224330211902961),
            GoldilocksField(7824009215589565948),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6749863180354359437),
            GoldilocksField(12030774021700161866),
            GoldilocksField(11817590136315683403),
            GoldilocksField(8080365152261516230),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14160037262311733630),
            GoldilocksField(17840299508729756742),
            GoldilocksField(3482889118248158271),
            GoldilocksField(249068128801380457),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11367409389017087085),
            GoldilocksField(14464547095499011834),
            GoldilocksField(8200441287272857264),
            GoldilocksField(11398821608595221338),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14443814143135026367),
            GoldilocksField(2029068062387494550),
            GoldilocksField(8970556336518972930),
            GoldilocksField(294406088566797823),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6401352370952695742),
            GoldilocksField(5408259903763061304),
            GoldilocksField(4583538490395829522),
            GoldilocksField(12651022540700461644),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17758912517009623967),
            GoldilocksField(13746675254972493181),
            GoldilocksField(10095585607879743772),
            GoldilocksField(4334681488825988341),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5795866725609413486),
            GoldilocksField(2991540287176729659),
            GoldilocksField(1478744581180022670),
            GoldilocksField(15550911913072389837),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12063588905302093845),
            GoldilocksField(4889092733892969793),
            GoldilocksField(4332285546772324876),
            GoldilocksField(17067887182003401893),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(182783030847032846),
            GoldilocksField(7184550624572312132),
            GoldilocksField(12206846587050398896),
            GoldilocksField(18271036869950964521),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3113645084104670474),
            GoldilocksField(9525273469596747439),
            GoldilocksField(4287396330774041595),
            GoldilocksField(11251297667986132883),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11794156500384242160),
            GoldilocksField(5571037338735571288),
            GoldilocksField(9539509114494366966),
            GoldilocksField(1065321648730689501),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1018009965349502587),
            GoldilocksField(12857535650671379527),
            GoldilocksField(12352205227828506773),
            GoldilocksField(3790986272598640258),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7252590646387477818),
            GoldilocksField(7419944988880144660),
            GoldilocksField(9765445740671591460),
            GoldilocksField(7145600243888014687),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17908911921154096470),
            GoldilocksField(17294937971911474216),
            GoldilocksField(10685568048071826435),
            GoldilocksField(16940163405963189893),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12441449852558747894),
            GoldilocksField(8930974459850479325),
            GoldilocksField(15163123289315657051),
            GoldilocksField(17116140197322456174),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12704364292314443138),
            GoldilocksField(15379444422363159094),
            GoldilocksField(17366974712273845794),
            GoldilocksField(5068279643735613531),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7234112203034812972),
            GoldilocksField(1022590994358889676),
            GoldilocksField(4129927921657068000),
            GoldilocksField(13827606089033794551),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2036433289763971893),
            GoldilocksField(4333576616218460483),
            GoldilocksField(12454264773102747655),
            GoldilocksField(1018627294828248437),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1900300949531776174),
            GoldilocksField(8404278790988138142),
            GoldilocksField(6968601042333330384),
            GoldilocksField(13858902261297563191),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15490326045359154056),
            GoldilocksField(9849074829805719124),
            GoldilocksField(17995589730513169355),
            GoldilocksField(16124028733193840877),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8684423328796282268),
            GoldilocksField(3174179041736285043),
            GoldilocksField(2821338587803837138),
            GoldilocksField(12091769858712668653),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9250780254588134603),
            GoldilocksField(1003485664552397217),
            GoldilocksField(11263678778156780777),
            GoldilocksField(3971377974538709794),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18026083960134858672),
            GoldilocksField(6659278048401806727),
            GoldilocksField(537840870976677873),
            GoldilocksField(11812027127253407888),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18389524021367211944),
            GoldilocksField(13344177161371520923),
            GoldilocksField(7643236055313052441),
            GoldilocksField(2910420061358885730),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14376889334062552214),
            GoldilocksField(13018301355152635197),
            GoldilocksField(13754782570295954115),
            GoldilocksField(3714907825013535192),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17556112982795307272),
            GoldilocksField(5922295967354695802),
            GoldilocksField(12577688740222160076),
            GoldilocksField(5563017257345383960),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4358207142040708503),
            GoldilocksField(7383818944480406721),
            GoldilocksField(11653349289572694275),
            GoldilocksField(8545349151307907661),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13708648929688227806),
            GoldilocksField(17210889030207462806),
            GoldilocksField(5743963048138102540),
            GoldilocksField(12455240155621830483),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3582775053855021797),
            GoldilocksField(16416233258899938455),
            GoldilocksField(15884725261349411701),
            GoldilocksField(11910867100285516321),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1998344563020625004),
            GoldilocksField(2647425199261574110),
            GoldilocksField(17558083012825951369),
            GoldilocksField(8243911964169473527),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12510248068464068665),
            GoldilocksField(11274088906389707366),
            GoldilocksField(6661087763502778037),
            GoldilocksField(9576362924786951999),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11638073050120565678),
            GoldilocksField(13123314233597623925),
            GoldilocksField(16789966691232029625),
            GoldilocksField(10937771642334943767),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16174353014275502077),
            GoldilocksField(17804972341018387714),
            GoldilocksField(4527314640461155401),
            GoldilocksField(5441825465087079175),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6855422037479437786),
            GoldilocksField(8303132197908945481),
            GoldilocksField(5771127959992898643),
            GoldilocksField(10062799145588897704),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12637136707723124128),
            GoldilocksField(4684909490757254211),
            GoldilocksField(1398380186929678020),
            GoldilocksField(2731660789619930801),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17219610741149524610),
            GoldilocksField(13127904385584588007),
            GoldilocksField(11007961533592285096),
            GoldilocksField(15861185438905056824),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12202677901228759790),
            GoldilocksField(6484015381545504640),
            GoldilocksField(11907201375158536937),
            GoldilocksField(17092262115344305391),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6219197185108575530),
            GoldilocksField(15245480309992475481),
            GoldilocksField(17762982936834099214),
            GoldilocksField(2884313249471969434),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16787761823937674874),
            GoldilocksField(3992989414702590371),
            GoldilocksField(2663777782651468847),
            GoldilocksField(16254262247565591891),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3195350176370082860),
            GoldilocksField(6727008687443189966),
            GoldilocksField(4511469798195767724),
            GoldilocksField(18445643483134438342),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14918509584990564895),
            GoldilocksField(15218935159979954882),
            GoldilocksField(11418545768384895686),
            GoldilocksField(1779192380498080201),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1399421711838602972),
            GoldilocksField(7520452154625011845),
            GoldilocksField(4514782940489541178),
            GoldilocksField(4526885572495266906),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1077052406781215009),
            GoldilocksField(17688678477897632628),
            GoldilocksField(6948405482680547671),
            GoldilocksField(17307738082078644719),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9220335152488411627),
            GoldilocksField(10713671221322544691),
            GoldilocksField(16710716454119528239),
            GoldilocksField(14119420091692765134),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(728148009432816091),
            GoldilocksField(10517380798896161873),
            GoldilocksField(1217516378012043233),
            GoldilocksField(15913263091619556628),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1700724502089551475),
            GoldilocksField(13211218573479198165),
            GoldilocksField(10607981598922375181),
            GoldilocksField(6682135604965087325),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17545415587281057492),
            GoldilocksField(10103697357317347438),
            GoldilocksField(5058119463233261352),
            GoldilocksField(206816009529956571),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11461166877009997879),
            GoldilocksField(14200250553046752496),
            GoldilocksField(274437814764342741),
            GoldilocksField(17314202968917760367),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11745932595797211906),
            GoldilocksField(5764266944401510360),
            GoldilocksField(2867151494910623889),
            GoldilocksField(4285644453143350030),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12005768100793945373),
            GoldilocksField(4997523190780249276),
            GoldilocksField(15480694679082448423),
            GoldilocksField(1658453512016188300),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8065847398766233202),
            GoldilocksField(5780142161076358372),
            GoldilocksField(11448541298713081078),
            GoldilocksField(16134061078677440036),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7011363852882466765),
            GoldilocksField(16142031590147205627),
            GoldilocksField(3173496646702774047),
            GoldilocksField(5516469867155455585),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1793532695479046827),
            GoldilocksField(13130214383195542288),
            GoldilocksField(14518271883359587232),
            GoldilocksField(11270161111396828589),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2009206307273347872),
            GoldilocksField(1540873930424945164),
            GoldilocksField(12071538115013393241),
            GoldilocksField(5521742348437646246),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18121308019890390686),
            GoldilocksField(17379538085356078840),
            GoldilocksField(11849282569894231576),
            GoldilocksField(2968662302247924778),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5846938751682625274),
            GoldilocksField(20147047181291160),
            GoldilocksField(5239073894756599074),
            GoldilocksField(1304319845717002947),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3245789425027569383),
            GoldilocksField(3477789785702314548),
            GoldilocksField(8585144163069453208),
            GoldilocksField(6463758054057527281),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10582012069454964501),
            GoldilocksField(13564459764401262339),
            GoldilocksField(11012537013066752267),
            GoldilocksField(7454014021468311056),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17799118580205810640),
            GoldilocksField(13792490502959483836),
            GoldilocksField(7374546459649699424),
            GoldilocksField(13822101439808652381),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17145728550648178350),
            GoldilocksField(10681398235654349846),
            GoldilocksField(5385109216772736085),
            GoldilocksField(10954081145644968644),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12128447599746108472),
            GoldilocksField(73888401667607957),
            GoldilocksField(6343538633532844056),
            GoldilocksField(10155492302459329110),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5727298273899386679),
            GoldilocksField(13078284813948597127),
            GoldilocksField(11115042896766135903),
            GoldilocksField(10443876084791685936),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7407432915255027930),
            GoldilocksField(17162165482735440015),
            GoldilocksField(7528666995691711229),
            GoldilocksField(9863437624778565799),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13679059962044697046),
            GoldilocksField(16039119297708171754),
            GoldilocksField(15931717700568491257),
            GoldilocksField(11045298599255665398),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11023068862750392985),
            GoldilocksField(18437832700328416192),
            GoldilocksField(18242774327592530927),
            GoldilocksField(12463843430073719003),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17678933804068244838),
            GoldilocksField(809962503438901955),
            GoldilocksField(13848796879779048132),
            GoldilocksField(1463371556005694132),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2086753616967879613),
            GoldilocksField(17227201655750754808),
            GoldilocksField(5705592184289285458),
            GoldilocksField(17741664370128348499),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9461751647596337206),
            GoldilocksField(874182844346225169),
            GoldilocksField(7700440236025330552),
            GoldilocksField(10148777516754859805),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4685030150521725614),
            GoldilocksField(15575520938151603811),
            GoldilocksField(7327546702911848459),
            GoldilocksField(17644215827154755710),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2532723119447248178),
            GoldilocksField(6289255689491141196),
            GoldilocksField(9145721163442538621),
            GoldilocksField(16802983797178535691),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3632469679207659476),
            GoldilocksField(10367626157494047944),
            GoldilocksField(9443672710462449155),
            GoldilocksField(4154099357790086310),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9397374836039929792),
            GoldilocksField(5633791476703157892),
            GoldilocksField(17908039191567383270),
            GoldilocksField(8496879210046664635),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1609539175460831676),
            GoldilocksField(18440857799413008057),
            GoldilocksField(8183366227940766025),
            GoldilocksField(4259866668081456348),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14882794260594549624),
            GoldilocksField(1074951957523776731),
            GoldilocksField(84720549748135043),
            GoldilocksField(4501260285314095714),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10058551060314061856),
            GoldilocksField(7664230852497449756),
            GoldilocksField(9812167809762517103),
            GoldilocksField(876612192780123625),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3206954960825415551),
            GoldilocksField(15939755671821687020),
            GoldilocksField(9873578085506933720),
            GoldilocksField(16723939216465467903),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3380221374763962790),
            GoldilocksField(11204148858032949889),
            GoldilocksField(12036262174462099288),
            GoldilocksField(7497408992441863651),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9455749664258118701),
            GoldilocksField(14264687644038864090),
            GoldilocksField(7854675853908081495),
            GoldilocksField(12391119362763796703),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11996001199006480836),
            GoldilocksField(832835612513634290),
            GoldilocksField(5490993732271688814),
            GoldilocksField(13463201622563924613),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17775126282299744884),
            GoldilocksField(14702936474476995681),
            GoldilocksField(15240773723754235019),
            GoldilocksField(12720158003938948789),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14144898181496665298),
            GoldilocksField(10303720051277613600),
            GoldilocksField(17053616334635615003),
            GoldilocksField(11487571356529795725),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8475575969430002657),
            GoldilocksField(13467172607472833848),
            GoldilocksField(1425735344281562427),
            GoldilocksField(14024995706592488633),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12800828153352412585),
            GoldilocksField(11463115125535014059),
            GoldilocksField(16930962871987772931),
            GoldilocksField(8934902251245632027),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17463881778289860212),
            GoldilocksField(6783537091990407698),
            GoldilocksField(3280034717842249569),
            GoldilocksField(10383296434134940906),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1368894143476062078),
            GoldilocksField(6118072818495411835),
            GoldilocksField(5982902643334248446),
            GoldilocksField(12447017893851264930),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(156994357759399341),
            GoldilocksField(4013339109008729724),
            GoldilocksField(9819365827272359433),
            GoldilocksField(17675750393671408002),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4613346453006084674),
            GoldilocksField(17080838317084049669),
            GoldilocksField(13537333367353794645),
            GoldilocksField(4106609446074830320),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4601514614917822331),
            GoldilocksField(2349622085626659284),
            GoldilocksField(264935800320326754),
            GoldilocksField(9477088102252838745),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(607454875222528613),
            GoldilocksField(9485780999822800771),
            GoldilocksField(7558987755674340489),
            GoldilocksField(5485040657333678199),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13054270670294635143),
            GoldilocksField(7096486353975743156),
            GoldilocksField(17114165612779795091),
            GoldilocksField(15584051663210429038),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9213323336251465972),
            GoldilocksField(4929419520147414817),
            GoldilocksField(5190968750194151355),
            GoldilocksField(12376418565035584362),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16119417124575933456),
            GoldilocksField(36659182196507033),
            GoldilocksField(11554981366654521717),
            GoldilocksField(2079451357715720036),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5879743655869346432),
            GoldilocksField(1218901349904579984),
            GoldilocksField(18138925560373533085),
            GoldilocksField(14320900466896159643),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12758953586258238333),
            GoldilocksField(8321799178646722257),
            GoldilocksField(6680269408748210459),
            GoldilocksField(905098642962251583),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7381410940548312978),
            GoldilocksField(1870736606289997878),
            GoldilocksField(3552160511274436154),
            GoldilocksField(13122148688314873488),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6942187887450249490),
            GoldilocksField(14801706795320544049),
            GoldilocksField(6402424275000376538),
            GoldilocksField(5923890749245920355),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9437917597950791581),
            GoldilocksField(3716463232931868827),
            GoldilocksField(6648107265367197839),
            GoldilocksField(4373076117517236213),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2407265400786951732),
            GoldilocksField(11712331041041214387),
            GoldilocksField(15109897221535804167),
            GoldilocksField(5139531523163788174),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11779629181124612296),
            GoldilocksField(8615913443458820902),
            GoldilocksField(17063400279499708527),
            GoldilocksField(15441437603235924139),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17033538739458109862),
            GoldilocksField(14929584793263994216),
            GoldilocksField(5887548192806021653),
            GoldilocksField(6806588971724158821),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7072952068616061136),
            GoldilocksField(803059974280608952),
            GoldilocksField(17986284342363850369),
            GoldilocksField(5143939515453626599),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13347205093755629633),
            GoldilocksField(647795142315298866),
            GoldilocksField(13908520264518045674),
            GoldilocksField(7855876904108434085),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4296200462132623050),
            GoldilocksField(2391741256650982481),
            GoldilocksField(10834202731478975494),
            GoldilocksField(16336886461168668097),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2725044908269692403),
            GoldilocksField(1444755042736862221),
            GoldilocksField(11867259274585644677),
            GoldilocksField(377577876230012758),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13800479772184602554),
            GoldilocksField(7735111957656624342),
            GoldilocksField(7302224340321803456),
            GoldilocksField(7926337998638565591),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16456637132200618822),
            GoldilocksField(16527369927784646945),
            GoldilocksField(11439744605086083844),
            GoldilocksField(16102588384397371573),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3231001968431993480),
            GoldilocksField(17534907581446945906),
            GoldilocksField(2941762689215948299),
            GoldilocksField(10519505725701980317),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4698712738642915652),
            GoldilocksField(2306550469352464316),
            GoldilocksField(11121793241956802841),
            GoldilocksField(5370525198035048191),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15877985122266676019),
            GoldilocksField(14415772867316813608),
            GoldilocksField(6376324116685682939),
            GoldilocksField(11604369730295179095),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6716117353868216660),
            GoldilocksField(15990533724580869292),
            GoldilocksField(8542460087663099411),
            GoldilocksField(15380627171291005721),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17897330575645843466),
            GoldilocksField(3274217444610214945),
            GoldilocksField(2872273831278085694),
            GoldilocksField(17976860418096570025),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7454119873964599653),
            GoldilocksField(13083409393478705440),
            GoldilocksField(10062396612832687364),
            GoldilocksField(8558291923918735302),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5684597124015387868),
            GoldilocksField(1344953815257328221),
            GoldilocksField(4690983525631019227),
            GoldilocksField(3112224305312080208),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11674147656547443313),
            GoldilocksField(11544991840759351685),
            GoldilocksField(15129703147478163917),
            GoldilocksField(17806130596184407395),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12949156933592247077),
            GoldilocksField(13884183771177305077),
            GoldilocksField(7644395926568062126),
            GoldilocksField(7830332941772232953),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17335499182689544663),
            GoldilocksField(5275265671789596540),
            GoldilocksField(14406371704901586435),
            GoldilocksField(2614659496156978599),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1958563107332709628),
            GoldilocksField(10667671354235779279),
            GoldilocksField(2950460181506108497),
            GoldilocksField(13894119345745556182),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18015969540381608498),
            GoldilocksField(16324646613336663308),
            GoldilocksField(10783091047047119948),
            GoldilocksField(16026602376283907410),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17344591860158710247),
            GoldilocksField(13832409594972394506),
            GoldilocksField(1816075113486933599),
            GoldilocksField(17432306307869755802),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12074098116604675488),
            GoldilocksField(16559583756768465422),
            GoldilocksField(16570590909145690548),
            GoldilocksField(18428212934586674581),
        ],
    }),
];
