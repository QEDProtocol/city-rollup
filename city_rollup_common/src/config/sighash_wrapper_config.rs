use city_crypto::hash::qhashout::QHashOut;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::HashOut};

type F = GoldilocksField;
pub const SIGHASH_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 16;
pub const SIGHASH_CIRCUIT_MAX_WITHDRAWALS: usize = 2;
pub const SIGHASH_CIRCUIT_MAX_DEPOSITS: usize = 2;
pub const SIGHASH_WHITELIST_TREE_ROOT: QHashOut<F> = QHashOut(HashOut {
    elements: [
        GoldilocksField(2281708616773938568),
        GoldilocksField(7386481742721131353),
        GoldilocksField(3675052136698407730),
        GoldilocksField(16149320100262733736),
    ],
});

pub const SIGHASH_CIRCUIT_FINGERPRINTS: [QHashOut<F>; 162] = [
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18359484507922091016),
            GoldilocksField(2734588511184488255),
            GoldilocksField(17284250790833320602),
            GoldilocksField(1635444703546793854),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2970293748722199843),
            GoldilocksField(6442093788332070143),
            GoldilocksField(6607296600289036706),
            GoldilocksField(16814879991732689431),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14789074234800680435),
            GoldilocksField(5747884982822676146),
            GoldilocksField(3061735206687970024),
            GoldilocksField(17371710268189814976),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4218184755813796563),
            GoldilocksField(3654015762516594771),
            GoldilocksField(989425725278609820),
            GoldilocksField(18225566340836563549),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9009293143396713886),
            GoldilocksField(10195782878279718528),
            GoldilocksField(4597558980725998316),
            GoldilocksField(12836143233503583476),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9876830487165359521),
            GoldilocksField(4224785714784142779),
            GoldilocksField(10220054294792692895),
            GoldilocksField(13224364391682842203),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(649121193207278852),
            GoldilocksField(12765502492900966322),
            GoldilocksField(10209322343965067611),
            GoldilocksField(4768792735989933670),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9483556336068356950),
            GoldilocksField(1242266665336284685),
            GoldilocksField(18404991548212532812),
            GoldilocksField(5605014438052574206),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8634647870419068755),
            GoldilocksField(1772696936734546074),
            GoldilocksField(3756529225225896958),
            GoldilocksField(13854372112321520819),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10255327237729438251),
            GoldilocksField(775550287194443196),
            GoldilocksField(1860376371278173680),
            GoldilocksField(13213636353896174924),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17805277476282877696),
            GoldilocksField(9125273192516563319),
            GoldilocksField(14372721207645960193),
            GoldilocksField(15765704984403721481),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16576430639760056581),
            GoldilocksField(7793986308125904544),
            GoldilocksField(8425457348286064080),
            GoldilocksField(14971309422978245729),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8712486588955043328),
            GoldilocksField(4713306189752871301),
            GoldilocksField(9599252599516224583),
            GoldilocksField(917860670294124165),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5275722332059956634),
            GoldilocksField(9975686723641038786),
            GoldilocksField(509327981689892711),
            GoldilocksField(11814612384739021229),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4567105462159899075),
            GoldilocksField(8154400665241680162),
            GoldilocksField(7059122061808880924),
            GoldilocksField(3264916043961965235),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4482995499458574404),
            GoldilocksField(15671867458800962800),
            GoldilocksField(2260496376810506998),
            GoldilocksField(4640786245372229475),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(661955132738438305),
            GoldilocksField(11137461415056876314),
            GoldilocksField(1049439133189530877),
            GoldilocksField(15128750619425194113),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14392661689944813225),
            GoldilocksField(5319904375742089920),
            GoldilocksField(9931817993579339705),
            GoldilocksField(11018222917657492116),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10062652981861605860),
            GoldilocksField(12270315640516753166),
            GoldilocksField(177955324114382197),
            GoldilocksField(16920684944836846147),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4094814859992986400),
            GoldilocksField(4981385090814141236),
            GoldilocksField(18134029132304156537),
            GoldilocksField(10156128924247127827),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10133250133469289335),
            GoldilocksField(13715172095045092191),
            GoldilocksField(3428362777945593336),
            GoldilocksField(10398112120336827468),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16878477721276002515),
            GoldilocksField(2303222982874466548),
            GoldilocksField(12369698881520548430),
            GoldilocksField(6981985617524620738),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17762512936890118305),
            GoldilocksField(3445185285328857595),
            GoldilocksField(11652959054233742402),
            GoldilocksField(14252579666241417700),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11573588523482385151),
            GoldilocksField(4964209635895217941),
            GoldilocksField(18186601392253878219),
            GoldilocksField(10009150051504092316),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5946627790194496593),
            GoldilocksField(13167574027180171231),
            GoldilocksField(4647253372018075222),
            GoldilocksField(7353684943479699823),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2415758339579352360),
            GoldilocksField(6176587737896507032),
            GoldilocksField(16975561105654265430),
            GoldilocksField(5719123123790274365),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9696834173529834011),
            GoldilocksField(5623422113044571737),
            GoldilocksField(5267907140370208801),
            GoldilocksField(9038275273599963504),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14233951120586812757),
            GoldilocksField(1897845597381601184),
            GoldilocksField(11056987490165832629),
            GoldilocksField(2553679924832186958),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7999469089209374219),
            GoldilocksField(7915397703535695584),
            GoldilocksField(3263253979114876230),
            GoldilocksField(6131989558061599026),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9117088766636477277),
            GoldilocksField(13657624322332631766),
            GoldilocksField(8513951855362196421),
            GoldilocksField(11524196689635276532),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7751846293120266933),
            GoldilocksField(8871670748115395466),
            GoldilocksField(11566795430393931388),
            GoldilocksField(7357343986239698221),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13807205135673197667),
            GoldilocksField(3462436534791074559),
            GoldilocksField(11346768069827124103),
            GoldilocksField(13992077759690912525),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16578026260592559343),
            GoldilocksField(1344177824615715464),
            GoldilocksField(18347759933516306115),
            GoldilocksField(14020420283201759478),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4026059090701030719),
            GoldilocksField(6964100315222096418),
            GoldilocksField(12815809379205602446),
            GoldilocksField(3653414530272147858),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15383160533008217050),
            GoldilocksField(9449694484112388529),
            GoldilocksField(9498148772152905826),
            GoldilocksField(6524626681862952216),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3444738633960871166),
            GoldilocksField(14554595926845910970),
            GoldilocksField(17309740554370334134),
            GoldilocksField(17694410206122353005),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17571124705991775305),
            GoldilocksField(4812614035519249127),
            GoldilocksField(16945541015038861079),
            GoldilocksField(9174770671732933622),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15399296634037228454),
            GoldilocksField(1835354927314913232),
            GoldilocksField(9448638565476438020),
            GoldilocksField(3414217059405070571),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2086531550755738911),
            GoldilocksField(17028191851792240846),
            GoldilocksField(4710379798245728164),
            GoldilocksField(6182091347979122243),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12163025612089247495),
            GoldilocksField(17763000761489682947),
            GoldilocksField(4840972400531294907),
            GoldilocksField(7016140822128841482),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8351037383100782035),
            GoldilocksField(10209399418057465526),
            GoldilocksField(5330111795887279335),
            GoldilocksField(5914957879725255194),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(765084583514138301),
            GoldilocksField(12287354041584668819),
            GoldilocksField(139748169355741733),
            GoldilocksField(10281200004007169260),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5885508373534128989),
            GoldilocksField(14075995456253595581),
            GoldilocksField(10605972006894581861),
            GoldilocksField(9257595053487990510),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6069254569457340899),
            GoldilocksField(10804262158644435044),
            GoldilocksField(16542068745351798147),
            GoldilocksField(5689759783381801248),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13565934960604355533),
            GoldilocksField(8530908676260262156),
            GoldilocksField(7880296132268169777),
            GoldilocksField(14231521428446071087),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3903541717009419979),
            GoldilocksField(6095877410696204259),
            GoldilocksField(9666388253766514315),
            GoldilocksField(1349610116490041486),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10541910547023832130),
            GoldilocksField(6163050148823401293),
            GoldilocksField(9551871045353830241),
            GoldilocksField(13840425314099962665),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3172875656398401312),
            GoldilocksField(8994303944955930612),
            GoldilocksField(15387088089461190368),
            GoldilocksField(8517245490831871122),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16736795163852420605),
            GoldilocksField(11004637595099461284),
            GoldilocksField(5873444904697800467),
            GoldilocksField(2311956035731318135),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2082533248098580428),
            GoldilocksField(9326423217045688060),
            GoldilocksField(7202332934801647517),
            GoldilocksField(5847787137250297488),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17711444859374502723),
            GoldilocksField(9137735138860483103),
            GoldilocksField(12956587167102460007),
            GoldilocksField(10068279052892749476),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17444207934210541531),
            GoldilocksField(3432224498654290378),
            GoldilocksField(10698348485429372184),
            GoldilocksField(7991501205888693821),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15733582001313732649),
            GoldilocksField(4011305744205493706),
            GoldilocksField(2491712935922262270),
            GoldilocksField(12636958593782202118),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1152224938868747176),
            GoldilocksField(15558860549609505990),
            GoldilocksField(10067724996501980292),
            GoldilocksField(4811063943394498762),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7815487217030442332),
            GoldilocksField(1869698869518664384),
            GoldilocksField(14226192520837955278),
            GoldilocksField(6784332967745565523),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4884913581025897412),
            GoldilocksField(15083743245246641577),
            GoldilocksField(7397091679791793951),
            GoldilocksField(14535888871706479306),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15010874821550680139),
            GoldilocksField(12463095721617457937),
            GoldilocksField(6546761607999853255),
            GoldilocksField(1397730713030534491),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7268566941831968982),
            GoldilocksField(8331159423273170940),
            GoldilocksField(6237760912663590804),
            GoldilocksField(3797969975071227355),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14925760480280470117),
            GoldilocksField(16981736712452418101),
            GoldilocksField(2632028731269098416),
            GoldilocksField(548598821155734082),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17800825736580174720),
            GoldilocksField(8936800513029922590),
            GoldilocksField(10626561068673288153),
            GoldilocksField(11383533360112353494),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14237281478842874928),
            GoldilocksField(17062203331939589415),
            GoldilocksField(9220717898543889246),
            GoldilocksField(11156975206822415360),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6157705474374276171),
            GoldilocksField(5320883178886684660),
            GoldilocksField(17268343941211992235),
            GoldilocksField(2044325041754537103),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13172032557114677769),
            GoldilocksField(3488236698513033473),
            GoldilocksField(4748169657334469025),
            GoldilocksField(8070021260231273040),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6827403663468156607),
            GoldilocksField(15398168829057551906),
            GoldilocksField(6696776224019604016),
            GoldilocksField(13249342050615459061),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8631433945047174420),
            GoldilocksField(16261131678496129110),
            GoldilocksField(16365608764276715463),
            GoldilocksField(12325017488375070066),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13620292742785574103),
            GoldilocksField(1076538218456256227),
            GoldilocksField(10617244760455916996),
            GoldilocksField(11729649549023040132),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5384903801881297865),
            GoldilocksField(3178673960734730668),
            GoldilocksField(16724226238417972436),
            GoldilocksField(7904090070466253168),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(993499087671783070),
            GoldilocksField(17567662449042324857),
            GoldilocksField(7920237984630265171),
            GoldilocksField(12791313778032453856),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2058619074066710331),
            GoldilocksField(7272760124648472828),
            GoldilocksField(11460484317515991057),
            GoldilocksField(10680707440531770484),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1208523114368883956),
            GoldilocksField(15756495094901321256),
            GoldilocksField(17192660433723458059),
            GoldilocksField(13852175892660495246),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2096250912697960074),
            GoldilocksField(2238335434464502534),
            GoldilocksField(2582223406778693022),
            GoldilocksField(7340421615398999566),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11951467855330463670),
            GoldilocksField(8196486971586032837),
            GoldilocksField(3018245987176866119),
            GoldilocksField(1459717608843323349),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3464268359530808838),
            GoldilocksField(4718179216315744215),
            GoldilocksField(11495915878070761888),
            GoldilocksField(1283316705368554645),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15738693576180495168),
            GoldilocksField(9715866486706669340),
            GoldilocksField(5337741256405000737),
            GoldilocksField(17981127734906029780),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14973984357263211466),
            GoldilocksField(12243710644718759096),
            GoldilocksField(12842730429262801715),
            GoldilocksField(14149145824522721673),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14977677191660938273),
            GoldilocksField(13526483286155510617),
            GoldilocksField(597245961171394987),
            GoldilocksField(3505586142738704413),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8522714992248764085),
            GoldilocksField(10550940258908250672),
            GoldilocksField(3128562865632210758),
            GoldilocksField(11320663927235976240),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4593453918240149699),
            GoldilocksField(3581975563005003860),
            GoldilocksField(17389704519858419056),
            GoldilocksField(2652815152819031132),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15701672464299813956),
            GoldilocksField(2995237039502393068),
            GoldilocksField(11585731289779226835),
            GoldilocksField(871239103865687260),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17534522501722459074),
            GoldilocksField(9378637853153056736),
            GoldilocksField(7784782005065243956),
            GoldilocksField(1962380051670971226),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4983656604364649922),
            GoldilocksField(12708339470079276660),
            GoldilocksField(5165741407547261541),
            GoldilocksField(15171019122826388861),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3257441528886314665),
            GoldilocksField(15518477004506562429),
            GoldilocksField(1727986009643389137),
            GoldilocksField(4269839184428167981),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2121645176640199437),
            GoldilocksField(11967961420167513818),
            GoldilocksField(6834341318260501325),
            GoldilocksField(17036893034948054288),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17981244585123974779),
            GoldilocksField(3841145182247828959),
            GoldilocksField(5512205388949322173),
            GoldilocksField(7191865654528719155),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15615873454173031028),
            GoldilocksField(224566920345429569),
            GoldilocksField(2926537864631187050),
            GoldilocksField(14358505608183770688),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7935287151164766555),
            GoldilocksField(1838479534849778049),
            GoldilocksField(16037029909283350983),
            GoldilocksField(5084694517684638824),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17319197504249570492),
            GoldilocksField(11500191574354775420),
            GoldilocksField(6868120901114062902),
            GoldilocksField(9196349237807664083),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1961436516936237763),
            GoldilocksField(16649646439255710385),
            GoldilocksField(5477665319934089899),
            GoldilocksField(7739124515040503605),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7861008854500335596),
            GoldilocksField(11639507943894516274),
            GoldilocksField(17272095935189581688),
            GoldilocksField(6286113802256796051),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13234704302604368291),
            GoldilocksField(15213932311639725043),
            GoldilocksField(15768627338321887459),
            GoldilocksField(15066411438586448612),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6789621260045815775),
            GoldilocksField(16407966605179018935),
            GoldilocksField(7012493513184814644),
            GoldilocksField(13645700168299818416),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3770907750080962277),
            GoldilocksField(7779207517176063330),
            GoldilocksField(7631998350613370857),
            GoldilocksField(3055622980977076545),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15756090191177608030),
            GoldilocksField(15912328325404873308),
            GoldilocksField(13452323807691667225),
            GoldilocksField(4955949838316280783),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13689385650016417548),
            GoldilocksField(18244685491944528809),
            GoldilocksField(4164812929098307499),
            GoldilocksField(1079763657836904312),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2031075402331154832),
            GoldilocksField(16415644798625982762),
            GoldilocksField(15319457156798320060),
            GoldilocksField(17860701386376827455),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15301360236474084984),
            GoldilocksField(6395827137737582407),
            GoldilocksField(2809626333920805316),
            GoldilocksField(12362167908188775475),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8170845438162093186),
            GoldilocksField(11747171640626959922),
            GoldilocksField(12748017616086293260),
            GoldilocksField(14744359360394039295),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8497724943088033768),
            GoldilocksField(5884456715144807183),
            GoldilocksField(6313226526131175981),
            GoldilocksField(14322064525760518413),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10617987321405422320),
            GoldilocksField(12346117017308205159),
            GoldilocksField(2994788527565922251),
            GoldilocksField(9122162763516230762),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4382804977668544985),
            GoldilocksField(1018051907149622353),
            GoldilocksField(14564085524932117463),
            GoldilocksField(12058221965202027714),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2114786270967866703),
            GoldilocksField(3079719376924301961),
            GoldilocksField(8890686042353243058),
            GoldilocksField(17736136158093669156),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1460255652504548174),
            GoldilocksField(10840012489151114866),
            GoldilocksField(11640855127424591365),
            GoldilocksField(17272293013287686969),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4299717740578830069),
            GoldilocksField(16984965936872642847),
            GoldilocksField(1229638796360901732),
            GoldilocksField(12496156464414305441),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17827080908858113711),
            GoldilocksField(3829167737720577797),
            GoldilocksField(11685321167935933770),
            GoldilocksField(6295321388539034808),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5667197670639662245),
            GoldilocksField(5313515099145553600),
            GoldilocksField(6478627833553498436),
            GoldilocksField(8814593259496497135),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11388513334549527497),
            GoldilocksField(2915149098493970410),
            GoldilocksField(4879179011507289194),
            GoldilocksField(17525446250179074229),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11407979602985973166),
            GoldilocksField(12079719165713878158),
            GoldilocksField(2898798808069039610),
            GoldilocksField(335941483567264817),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9066158928814557275),
            GoldilocksField(5367742566296439172),
            GoldilocksField(16381624439171930179),
            GoldilocksField(11650495351177287657),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13386553880863654906),
            GoldilocksField(1197786928196549143),
            GoldilocksField(11113568725399108312),
            GoldilocksField(2842291555156208063),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(15172685739074984590),
            GoldilocksField(274630296068706500),
            GoldilocksField(8940286029883757673),
            GoldilocksField(3000472388270676558),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16532863828646140475),
            GoldilocksField(16069134272029614878),
            GoldilocksField(17707169255232698853),
            GoldilocksField(321954774279760701),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12622944598415729039),
            GoldilocksField(12272545936076623327),
            GoldilocksField(14456317309708154934),
            GoldilocksField(7026264158054132281),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6558247684199604494),
            GoldilocksField(10072695767593036068),
            GoldilocksField(2472818859058239960),
            GoldilocksField(13575248240511247722),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10798909040252027472),
            GoldilocksField(16775828565819294110),
            GoldilocksField(11159927808095099885),
            GoldilocksField(307580128902016823),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7138187833735262076),
            GoldilocksField(14275880868801340483),
            GoldilocksField(5244645718115685336),
            GoldilocksField(6937934825261862550),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8628751339684382258),
            GoldilocksField(962784985206604097),
            GoldilocksField(7705916318077014403),
            GoldilocksField(3678101549667805600),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7345122687417686617),
            GoldilocksField(3440578894507049070),
            GoldilocksField(17879705194799448014),
            GoldilocksField(4611683966626293631),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5998815526849053599),
            GoldilocksField(11082294951306839766),
            GoldilocksField(11563140524008770949),
            GoldilocksField(2219066044957620127),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7227592359837855696),
            GoldilocksField(7386372559950767842),
            GoldilocksField(2773282836264555461),
            GoldilocksField(16228692709774978417),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10217104648880341838),
            GoldilocksField(16871129219552919141),
            GoldilocksField(11443838403940980401),
            GoldilocksField(13238724603887745854),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3058118107820202095),
            GoldilocksField(896067926541304619),
            GoldilocksField(5816359455320182259),
            GoldilocksField(1717424463679346467),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10315199050399797937),
            GoldilocksField(8747545173491449476),
            GoldilocksField(46385483492327366),
            GoldilocksField(9146112055840638410),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(692040892631558804),
            GoldilocksField(2092215239658004337),
            GoldilocksField(6604964375107281708),
            GoldilocksField(15327301832373551895),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(17627565616019751728),
            GoldilocksField(10830036241947387612),
            GoldilocksField(17989024741571849119),
            GoldilocksField(8646916888052954915),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1541048690181804517),
            GoldilocksField(10705375248645904830),
            GoldilocksField(1647338114112752329),
            GoldilocksField(18268838567228018984),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14480740054308088836),
            GoldilocksField(1855825039671137889),
            GoldilocksField(6036633903800866215),
            GoldilocksField(6993665031399554782),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6642290840161959241),
            GoldilocksField(7853655846189794774),
            GoldilocksField(781050810676300938),
            GoldilocksField(17166202165294885120),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14544476469684813270),
            GoldilocksField(2367185846550660188),
            GoldilocksField(7372171191377546871),
            GoldilocksField(11936308435479879615),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16758983210103215144),
            GoldilocksField(8944757103572862417),
            GoldilocksField(9624469262920668627),
            GoldilocksField(3343391883832974917),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3040175377385895301),
            GoldilocksField(14939673200631571755),
            GoldilocksField(12503059307553599215),
            GoldilocksField(10499209018632688792),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(14411039901997580115),
            GoldilocksField(17118585007234181002),
            GoldilocksField(11226405383999668539),
            GoldilocksField(2166372269864125279),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8397324130052392147),
            GoldilocksField(15235586827183208605),
            GoldilocksField(13943209426757975033),
            GoldilocksField(3544689803405803607),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5868011465285525817),
            GoldilocksField(4663053283427041431),
            GoldilocksField(13790275545812224901),
            GoldilocksField(10478777782587323414),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2878286989835290407),
            GoldilocksField(1255068755457831619),
            GoldilocksField(3384943176093440167),
            GoldilocksField(349468211527486644),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2704681525370829833),
            GoldilocksField(6431372453171598671),
            GoldilocksField(4811837238747079408),
            GoldilocksField(5611019817511338397),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(7581598540379331203),
            GoldilocksField(3548788876363304437),
            GoldilocksField(17698457925471406540),
            GoldilocksField(1642579078556714505),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18439305917031192111),
            GoldilocksField(4179681506963403592),
            GoldilocksField(8277421779851991141),
            GoldilocksField(5651170184005069210),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(6675918075992367576),
            GoldilocksField(8455033844081081543),
            GoldilocksField(7555775474014108983),
            GoldilocksField(3518766320673865128),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1302533811929537569),
            GoldilocksField(11790790035635612300),
            GoldilocksField(17744467438957759280),
            GoldilocksField(12374927811584542025),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(11347263100845833975),
            GoldilocksField(18106291954471552995),
            GoldilocksField(10782453564205858084),
            GoldilocksField(13644689922927179481),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8126982304506889991),
            GoldilocksField(12348126166622891855),
            GoldilocksField(7106856803911950771),
            GoldilocksField(12412700417382736913),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8791696939590129184),
            GoldilocksField(14378165841235580204),
            GoldilocksField(11777797327537242537),
            GoldilocksField(3750426689851788743),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12362429011941871867),
            GoldilocksField(4109831914098720935),
            GoldilocksField(11780855228074338397),
            GoldilocksField(955718596626296429),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(18301476686144095679),
            GoldilocksField(12344647791825213259),
            GoldilocksField(10912337294247401103),
            GoldilocksField(13385206746759499287),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13081595502012645506),
            GoldilocksField(11963620261488786719),
            GoldilocksField(14155092651862408532),
            GoldilocksField(12604982866254317111),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(8649553759341119876),
            GoldilocksField(14145496465264549372),
            GoldilocksField(10307266138826764257),
            GoldilocksField(4764807916670035738),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(4553673938621779265),
            GoldilocksField(2243179311810089547),
            GoldilocksField(11015236366987554113),
            GoldilocksField(12655225389848680502),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5324547937784020561),
            GoldilocksField(11453041118438347857),
            GoldilocksField(4203911600272437098),
            GoldilocksField(13884126705381646537),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3929993867190859494),
            GoldilocksField(17002025277624393289),
            GoldilocksField(5336998663822422821),
            GoldilocksField(9910300777186244180),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12109663608677812185),
            GoldilocksField(9552363035760428921),
            GoldilocksField(8281619312979547966),
            GoldilocksField(13963606746663125659),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(16818357849386247568),
            GoldilocksField(14874500983323209003),
            GoldilocksField(3316919053167310608),
            GoldilocksField(9894382417733125869),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(12675979494244652667),
            GoldilocksField(13466555677558418466),
            GoldilocksField(6258784690417278437),
            GoldilocksField(8959148238049572246),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(10845348481005732465),
            GoldilocksField(16334494288633762274),
            GoldilocksField(4635806747641206872),
            GoldilocksField(12847469829555588515),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(2833249613111133192),
            GoldilocksField(6158447147771341821),
            GoldilocksField(4270048987866399105),
            GoldilocksField(7244033674896513591),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9801432509930681684),
            GoldilocksField(4513346274701727225),
            GoldilocksField(701815184331773878),
            GoldilocksField(12926522751543659582),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9578337580420908885),
            GoldilocksField(7326798249452252016),
            GoldilocksField(18067531789434633446),
            GoldilocksField(6588434293754044221),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(1243017661718478330),
            GoldilocksField(13722301145423929194),
            GoldilocksField(16159969563374872921),
            GoldilocksField(3939945498594776954),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(9876692235472851025),
            GoldilocksField(10762025706520947788),
            GoldilocksField(16172945960821551209),
            GoldilocksField(8365262546587142302),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(3210253607928073680),
            GoldilocksField(8970665767380780150),
            GoldilocksField(2731414532503791506),
            GoldilocksField(13413068684772687328),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(13331445369704859809),
            GoldilocksField(18316610396490640424),
            GoldilocksField(4992112762486022494),
            GoldilocksField(2343960100182172718),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(689695810024945148),
            GoldilocksField(12733744901724947018),
            GoldilocksField(10694478099216316978),
            GoldilocksField(2768378752961505239),
        ],
    }),
    QHashOut(HashOut {
        elements: [
            GoldilocksField(5125380660523732617),
            GoldilocksField(10050632128049812873),
            GoldilocksField(3087474110947558845),
            GoldilocksField(17222057891738390650),
        ],
    }),
];
