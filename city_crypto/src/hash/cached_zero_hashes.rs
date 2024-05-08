use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::HashOut;

use super::qhashout::QHashOut;
use super::traits::hasher::MerkleZeroHasherWithCache;
use super::traits::hasher::MerkleZeroHasherWithCacheMarkedLeaf;
use super::traits::hasher::PoseidonHasher;

impl MerkleZeroHasherWithCache<HashOut<GoldilocksField>> for PoseidonHasher {
    const CACHED_ZERO_HASHES: [HashOut<GoldilocksField>; 128] = [
        HashOut {
            elements: [
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(4330397376401421145),
                GoldilocksField(14124799381142128323),
                GoldilocksField(8742572140681234676),
                GoldilocksField(14345658006221440202),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13121882728673923020),
                GoldilocksField(10197653806804742863),
                GoldilocksField(16037207047953124082),
                GoldilocksField(2420399206709257475),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7052649073129349210),
                GoldilocksField(11107139769197583972),
                GoldilocksField(5114845353783771231),
                GoldilocksField(7453521209854829890),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5860469655587923524),
                GoldilocksField(10142584705005652295),
                GoldilocksField(1620588827255328039),
                GoldilocksField(17663938664361140288),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16854358529591173550),
                GoldilocksField(9704301947898025017),
                GoldilocksField(13222045073939169687),
                GoldilocksField(14989445859181028978),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2675805695450374474),
                GoldilocksField(6493392849121218307),
                GoldilocksField(15972287940310989584),
                GoldilocksField(5284431416427098307),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16823738737355150819),
                GoldilocksField(4366876208047374841),
                GoldilocksField(1642083707956929713),
                GoldilocksField(13216064879834397173),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(18334109492892739862),
                GoldilocksField(10192437552951753306),
                GoldilocksField(15211985613247588647),
                GoldilocksField(3157981091968158131),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(4369129498500264270),
                GoldilocksField(10758747855946482846),
                GoldilocksField(3238306058428322199),
                GoldilocksField(18226589090145367109),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14769473886748754115),
                GoldilocksField(10513963056908986963),
                GoldilocksField(8105478726930894327),
                GoldilocksField(14014796621245524545),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10191288259157808067),
                GoldilocksField(944536249556834531),
                GoldilocksField(16268598854718968908),
                GoldilocksField(2417244819673331317),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17088215091100491041),
                GoldilocksField(18086883194773274646),
                GoldilocksField(10296247222913205474),
                GoldilocksField(7017044080942280524),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2985877902215057279),
                GoldilocksField(14516746119572211305),
                GoldilocksField(594952314256159992),
                GoldilocksField(17038984393731825093),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(101510842507023404),
                GoldilocksField(2267676083447667738),
                GoldilocksField(18106248392660779137),
                GoldilocksField(17680390044293740318),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16662284396446084312),
                GoldilocksField(7269926520507830029),
                GoldilocksField(14791338760961128332),
                GoldilocksField(7825163129638412009),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12364052984629808614),
                GoldilocksField(13066500727264825316),
                GoldilocksField(6321076066274078148),
                GoldilocksField(11393071566019822187),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6163084833659416779),
                GoldilocksField(2853393070793212496),
                GoldilocksField(214169662941198197),
                GoldilocksField(766838854721082896),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15062514972738604859),
                GoldilocksField(4072732498117267624),
                GoldilocksField(11453597623878964866),
                GoldilocksField(15196232748141971349),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8105799423402967201),
                GoldilocksField(10398709180756906993),
                GoldilocksField(12579914275816041967),
                GoldilocksField(3722472173064824114),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(4869072528223352863),
                GoldilocksField(6275850450145071959),
                GoldilocksField(8159689720148436485),
                GoldilocksField(8979985763136073723),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8512358054591706621),
                GoldilocksField(12918418052549764713),
                GoldilocksField(3564884046313350424),
                GoldilocksField(18039231110525565261),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10074982884687544941),
                GoldilocksField(4177217016749721471),
                GoldilocksField(4797356481048217516),
                GoldilocksField(6983283665462696061),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7025400382759865156),
                GoldilocksField(2103688473762123306),
                GoldilocksField(8681027323514330807),
                GoldilocksField(13853995481224614401),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(3896366420105793420),
                GoldilocksField(17410332186442776169),
                GoldilocksField(7329967984378645716),
                GoldilocksField(6310665049578686403),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6574146240104132812),
                GoldilocksField(2239043898123515337),
                GoldilocksField(13809601679688051486),
                GoldilocksField(16196448971140258304),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7429917014148897946),
                GoldilocksField(13764740161233226515),
                GoldilocksField(14310941960777962392),
                GoldilocksField(10321132974520710857),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16852763145767657080),
                GoldilocksField(5650551567722662817),
                GoldilocksField(4688637260797538488),
                GoldilocksField(504212361217900660),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17594730245457333136),
                GoldilocksField(13719209718183388763),
                GoldilocksField(11444947689050098668),
                GoldilocksField(628489339233491445),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7731246070744876899),
                GoldilocksField(3033565575746121792),
                GoldilocksField(14735263366152051322),
                GoldilocksField(16212144996433476818),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9947841139978160787),
                GoldilocksField(692236217135079542),
                GoldilocksField(16309341595179079658),
                GoldilocksField(9294006745033445642),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8603459983426387388),
                GoldilocksField(1706773463182378335),
                GoldilocksField(10020230853197995171),
                GoldilocksField(2362856042482390481),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16463394126558395459),
                GoldilocksField(12818610997234032270),
                GoldilocksField(2968763245313636978),
                GoldilocksField(15445927884703223427),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16924929798993045119),
                GoldilocksField(9228476078763095559),
                GoldilocksField(3639599968030750173),
                GoldilocksField(9842693474971302918),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2488667422532942441),
                GoldilocksField(619530082608543022),
                GoldilocksField(3698308124541679027),
                GoldilocksField(1337151890861372088),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10420632113085830027),
                GoldilocksField(2043024317550638523),
                GoldilocksField(9353702824282721936),
                GoldilocksField(13923517817060358740),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2864602688424687291),
                GoldilocksField(3849603923476837883),
                GoldilocksField(15617889861797529219),
                GoldilocksField(12429234418051645329),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2558543962574772915),
                GoldilocksField(9272315342420626056),
                GoldilocksField(4474448392614911585),
                GoldilocksField(1483027055753170828),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15131845414406822716),
                GoldilocksField(5979581984005702075),
                GoldilocksField(6999690762874000865),
                GoldilocksField(9727258862093954055),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16947881275436717432),
                GoldilocksField(7978417559450660789),
                GoldilocksField(5545004785373663100),
                GoldilocksField(8368806924824039910),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7354616297401405606),
                GoldilocksField(1100245580527406969),
                GoldilocksField(10869738626706821039),
                GoldilocksField(2491999729156780167),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6177345289547001265),
                GoldilocksField(16195131218421201680),
                GoldilocksField(8918200175203848893),
                GoldilocksField(9312707430953302559),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15836003362881933006),
                GoldilocksField(11144515108225672409),
                GoldilocksField(11343144721272549260),
                GoldilocksField(4624035188702918165),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15522756684614080517),
                GoldilocksField(13324444309246397554),
                GoldilocksField(17436959028924305779),
                GoldilocksField(18372463735326354528),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7652363938180064696),
                GoldilocksField(4344124640903777315),
                GoldilocksField(13216060880354093579),
                GoldilocksField(13200660336625184843),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(753089390850896872),
                GoldilocksField(12954782300140288288),
                GoldilocksField(5141754559998369457),
                GoldilocksField(16520063853691468679),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16459832343128755954),
                GoldilocksField(10962772927553810074),
                GoldilocksField(6221943911030879674),
                GoldilocksField(17223904123471497456),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17250168555681557323),
                GoldilocksField(2182781226934133394),
                GoldilocksField(18037176460909035824),
                GoldilocksField(14302675719735762512),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11566828016613919825),
                GoldilocksField(8426608301810268318),
                GoldilocksField(12603194638379686261),
                GoldilocksField(12781546638928195534),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11791905468424391494),
                GoldilocksField(353659221674669618),
                GoldilocksField(2954515582080156582),
                GoldilocksField(15617503846144778809),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12046546760594461704),
                GoldilocksField(1281951533681157165),
                GoldilocksField(10510366796594587935),
                GoldilocksField(1585258450210845006),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16107156070019717001),
                GoldilocksField(5384663464106500047),
                GoldilocksField(12860401619817372004),
                GoldilocksField(10797003111418379959),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8380887666379750723),
                GoldilocksField(4340858402662168218),
                GoldilocksField(5588784725350549956),
                GoldilocksField(3717855405583580584),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12350761983522803199),
                GoldilocksField(11629549689432119006),
                GoldilocksField(9356251521583330692),
                GoldilocksField(1763249683801623201),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5953334232381139661),
                GoldilocksField(18330852534639214342),
                GoldilocksField(9077267474540153872),
                GoldilocksField(8746348987390868438),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10539118579154381997),
                GoldilocksField(17127477609463226321),
                GoldilocksField(1631559647739184593),
                GoldilocksField(8422435084782312186),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12731093934649176641),
                GoldilocksField(17896569229540401625),
                GoldilocksField(17267231471603959652),
                GoldilocksField(15919122861351876841),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9216170438539790003),
                GoldilocksField(17899919792125268405),
                GoldilocksField(7770066510145848304),
                GoldilocksField(7399126282406819121),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12999900054714992159),
                GoldilocksField(9111710780146683360),
                GoldilocksField(2059907869783196340),
                GoldilocksField(1375263095716470201),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9229289078495900556),
                GoldilocksField(17561226985028096630),
                GoldilocksField(7202173456809480783),
                GoldilocksField(6438426075407719886),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5180822437522073905),
                GoldilocksField(16008390066609832754),
                GoldilocksField(18037924952145473030),
                GoldilocksField(5507677383726653043),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17083848998177046445),
                GoldilocksField(15548671076670207527),
                GoldilocksField(7110370156869873291),
                GoldilocksField(17694505563696524810),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9905054909759422851),
                GoldilocksField(2256149300669774275),
                GoldilocksField(10823691489106488104),
                GoldilocksField(16995522931301483917),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(4015802642468318748),
                GoldilocksField(6735982660678943841),
                GoldilocksField(17319343432667373419),
                GoldilocksField(3599138393404706899),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10688047713234024277),
                GoldilocksField(9016556671592595466),
                GoldilocksField(6239880553981200190),
                GoldilocksField(251647142305382872),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6105393314971334364),
                GoldilocksField(8496238509745699284),
                GoldilocksField(13056510769289857027),
                GoldilocksField(14070846864809093740),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14445319591693342961),
                GoldilocksField(2101093573226624565),
                GoldilocksField(17138507147001079143),
                GoldilocksField(3073076417314301190),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(3248762874212385128),
                GoldilocksField(2669353020062613412),
                GoldilocksField(15140260944739582298),
                GoldilocksField(18302547056943318452),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13187461470308300539),
                GoldilocksField(5313680972168257602),
                GoldilocksField(14713863290231927335),
                GoldilocksField(8524944837817793747),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6736444608481166433),
                GoldilocksField(2035338806364807431),
                GoldilocksField(1221993307994384273),
                GoldilocksField(15249273592684385399),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15963295117392385071),
                GoldilocksField(17859488035979019650),
                GoldilocksField(16008630532523697014),
                GoldilocksField(14340690071965489891),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15786852763336438198),
                GoldilocksField(10899507674496533139),
                GoldilocksField(11706276358469688200),
                GoldilocksField(14076246040119814704),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13005695680808688691),
                GoldilocksField(14599807539382340192),
                GoldilocksField(9123524395477531261),
                GoldilocksField(3302319617854564490),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12647545642292131518),
                GoldilocksField(13054340139873503226),
                GoldilocksField(4104942492966302442),
                GoldilocksField(14785460214545951374),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12145203032282344677),
                GoldilocksField(5677006333415156410),
                GoldilocksField(14535869388646949163),
                GoldilocksField(11852750114402075515),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11212220522506851472),
                GoldilocksField(17305824071782807976),
                GoldilocksField(13895561172667173499),
                GoldilocksField(10166329586907814359),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15031286889097919562),
                GoldilocksField(1324850860357117632),
                GoldilocksField(10704878335525490727),
                GoldilocksField(6552851480900673495),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7075300658303314337),
                GoldilocksField(7843310150090273296),
                GoldilocksField(10109388471273636642),
                GoldilocksField(2018779330079355536),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7872141395095779165),
                GoldilocksField(5673399122088596117),
                GoldilocksField(15978936760803615870),
                GoldilocksField(10465652434400926706),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(182275601750219224),
                GoldilocksField(2852220150918408331),
                GoldilocksField(4223445253065790943),
                GoldilocksField(12618532050821288848),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6712151225375682294),
                GoldilocksField(5712062620167537207),
                GoldilocksField(17732708101593922837),
                GoldilocksField(6003674375002058874),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17930157576718976452),
                GoldilocksField(7042813770003311174),
                GoldilocksField(10147055593991405452),
                GoldilocksField(16476659124764495938),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10598652526993459074),
                GoldilocksField(12949600898067649801),
                GoldilocksField(6253124184860577720),
                GoldilocksField(8211108850268780660),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2103384426324262455),
                GoldilocksField(12115515654334724875),
                GoldilocksField(12838734626972420570),
                GoldilocksField(16358869782757201076),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2812563820153332707),
                GoldilocksField(17687993387907305983),
                GoldilocksField(6026568395874743064),
                GoldilocksField(11075830002453718343),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2031050619124185341),
                GoldilocksField(1101404102711994941),
                GoldilocksField(13987392891822993041),
                GoldilocksField(14511527341026434685),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5561233035383682398),
                GoldilocksField(8145535878904966949),
                GoldilocksField(5726009330200207924),
                GoldilocksField(5041973692999461630),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7378478920928418813),
                GoldilocksField(240450404700504455),
                GoldilocksField(17177322487057405298),
                GoldilocksField(3235964297969163530),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2631025201140398264),
                GoldilocksField(8739642693994914487),
                GoldilocksField(15983631006751703622),
                GoldilocksField(9271919979380781825),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9078619994338362307),
                GoldilocksField(2144719805640242715),
                GoldilocksField(5949839645737043977),
                GoldilocksField(17987537375692074056),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15703299244758847757),
                GoldilocksField(10237479507707081974),
                GoldilocksField(16159140912123177140),
                GoldilocksField(6916053329562594946),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2008905230162769674),
                GoldilocksField(778563327167966812),
                GoldilocksField(9023142614382901272),
                GoldilocksField(10579687424455663279),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5918609586520646904),
                GoldilocksField(5493709911865566882),
                GoldilocksField(6714426177939800030),
                GoldilocksField(4363038388817350382),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14124154566946968192),
                GoldilocksField(14797837159533557836),
                GoldilocksField(4497323119383238687),
                GoldilocksField(13957527756142492430),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(18213711226300683020),
                GoldilocksField(13754839422409192236),
                GoldilocksField(6119224989292258192),
                GoldilocksField(13243955243086343355),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(4888020708444645063),
                GoldilocksField(8651326230277567641),
                GoldilocksField(10055771106513080840),
                GoldilocksField(9718342223333551334),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6906257647590863271),
                GoldilocksField(5943701417303303045),
                GoldilocksField(4599369487791254927),
                GoldilocksField(2348982053200018605),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(1416509185911772096),
                GoldilocksField(550940063394709840),
                GoldilocksField(6527274302288182846),
                GoldilocksField(16795718617974593),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13567612369227729992),
                GoldilocksField(10937988580152659669),
                GoldilocksField(18136850493928090512),
                GoldilocksField(8498707328026945488),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13555656525371732560),
                GoldilocksField(14981991449200455311),
                GoldilocksField(15427943396918076055),
                GoldilocksField(1655137664584853809),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10317274538960393479),
                GoldilocksField(13936117070735902890),
                GoldilocksField(3289811001287730525),
                GoldilocksField(10355806364261290461),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(1102872660510277355),
                GoldilocksField(2190710156956538771),
                GoldilocksField(14236674262527540226),
                GoldilocksField(14536097873239257103),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10695315653051098334),
                GoldilocksField(8030285986436344422),
                GoldilocksField(15454879862922821727),
                GoldilocksField(2236756262355278575),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14213424163462412247),
                GoldilocksField(6993609101978428580),
                GoldilocksField(13570211413601271193),
                GoldilocksField(1664674736561894083),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9426119267652803899),
                GoldilocksField(5385583849570283439),
                GoldilocksField(8387465646415533185),
                GoldilocksField(4862448025870347107),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14754409489504780682),
                GoldilocksField(3612032561314266125),
                GoldilocksField(17477437432804773001),
                GoldilocksField(445199991733136232),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(3746834526650996498),
                GoldilocksField(12583783367333648152),
                GoldilocksField(1061470622401626801),
                GoldilocksField(2589482137512462630),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13533140977738430832),
                GoldilocksField(10062061273968479833),
                GoldilocksField(9725685130007740348),
                GoldilocksField(16497097183928357178),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13144285485279868119),
                GoldilocksField(4082101042507655201),
                GoldilocksField(12019413233860458726),
                GoldilocksField(3454796547475608022),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13253691564007581919),
                GoldilocksField(1976337399470560924),
                GoldilocksField(16067320056164865996),
                GoldilocksField(17423613029535586111),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10026078945909724048),
                GoldilocksField(1554944974195216216),
                GoldilocksField(11312828219580743432),
                GoldilocksField(15138886657370666864),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16711713583543518975),
                GoldilocksField(13370396718118928879),
                GoldilocksField(13870757116200339751),
                GoldilocksField(4714534636449060433),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13939440524698301346),
                GoldilocksField(8905967259628748834),
                GoldilocksField(13285773279811246083),
                GoldilocksField(5828656143746450870),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7959745668085560084),
                GoldilocksField(11328177091149267320),
                GoldilocksField(17614861725682081647),
                GoldilocksField(6626970770586299947),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12489319969324856588),
                GoldilocksField(2271441446053312817),
                GoldilocksField(15744264430517630150),
                GoldilocksField(18073189248477841368),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5053885937344034804),
                GoldilocksField(10371174610521952640),
                GoldilocksField(3529252918299790231),
                GoldilocksField(9210846005956324247),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13111888119242902725),
                GoldilocksField(11575649969247209511),
                GoldilocksField(14705830568163442720),
                GoldilocksField(16718570455257293963),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10311917907065411495),
                GoldilocksField(9067220426528716341),
                GoldilocksField(6926254564704393288),
                GoldilocksField(2540103339823634721),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(82940137876848047),
                GoldilocksField(4187659877170668778),
                GoldilocksField(11709538958801991737),
                GoldilocksField(8606405806165245200),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(3278897161726127180),
                GoldilocksField(1740841674356247952),
                GoldilocksField(3042306427545138616),
                GoldilocksField(3607849423436667420),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11571301186946206579),
                GoldilocksField(9654002896036126944),
                GoldilocksField(14495186073362022308),
                GoldilocksField(8583768910393503789),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(1753678296021747761),
                GoldilocksField(15625830691687265367),
                GoldilocksField(13394440457762095354),
                GoldilocksField(15442975094580612536),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11049512054443973691),
                GoldilocksField(4951810764889686957),
                GoldilocksField(3253848456007936936),
                GoldilocksField(12251513943682983680),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12776945152172194891),
                GoldilocksField(4657250314707084136),
                GoldilocksField(8866809485494533567),
                GoldilocksField(2718976634788294881),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(3141920725930852063),
                GoldilocksField(1604850316539440905),
                GoldilocksField(7103788112293470972),
                GoldilocksField(1759798822543824539),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5887324832033966576),
                GoldilocksField(15269945251255639671),
                GoldilocksField(10475125945250366169),
                GoldilocksField(4588920059532534839),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17560240928095887948),
                GoldilocksField(339351600890900315),
                GoldilocksField(1590663936866431790),
                GoldilocksField(10818704214216236348),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12859013487963271720),
                GoldilocksField(18068342177185331637),
                GoldilocksField(5027269237729179984),
                GoldilocksField(5564116628722363904),
            ],
        },
    ];
}

impl MerkleZeroHasherWithCacheMarkedLeaf<HashOut<GoldilocksField>> for PoseidonHasher {
    const CACHED_MARKED_LEAF_ZERO_HASHES: [HashOut<GoldilocksField>; 128] = [
        HashOut {
            elements: [
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6442606111422150320),
                GoldilocksField(5704244332762452547),
                GoldilocksField(4897226532477482799),
                GoldilocksField(12135336437794039610),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(808556306716190912),
                GoldilocksField(2476063296744350509),
                GoldilocksField(15121424568169165254),
                GoldilocksField(3029093053421045263),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12352321749544959065),
                GoldilocksField(5957845988768556333),
                GoldilocksField(15100136569072024617),
                GoldilocksField(16676339421322802800),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11676513847782856690),
                GoldilocksField(11358593067649481162),
                GoldilocksField(9343969531511723369),
                GoldilocksField(16050192720600814849),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7067272467782064710),
                GoldilocksField(1527966539952818982),
                GoldilocksField(8136769675347503390),
                GoldilocksField(4406543573748523830),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(371257336755096171),
                GoldilocksField(12660727904653319748),
                GoldilocksField(13497644411941779497),
                GoldilocksField(18329641640492503964),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17462588609252433262),
                GoldilocksField(6308399974825987705),
                GoldilocksField(11246036879296416044),
                GoldilocksField(1699588579966035392),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10592442612647489306),
                GoldilocksField(13626641172113024814),
                GoldilocksField(5208817656464894676),
                GoldilocksField(10444948860822448724),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(4347348823726450270),
                GoldilocksField(18346478006157677236),
                GoldilocksField(4542629529988803205),
                GoldilocksField(534809824023301308),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9695701940771125402),
                GoldilocksField(10799058527783262173),
                GoldilocksField(6118813008585250486),
                GoldilocksField(8792955908193094753),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9881731838825243287),
                GoldilocksField(10316601684741776174),
                GoldilocksField(15540520434151297193),
                GoldilocksField(13323926745203701243),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7593735662458093260),
                GoldilocksField(17743614875929349477),
                GoldilocksField(2605756623176371665),
                GoldilocksField(6522792836480148337),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13949815761935396135),
                GoldilocksField(7044411766837335933),
                GoldilocksField(3527982556051196377),
                GoldilocksField(6010641661278572926),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13892725284727366476),
                GoldilocksField(14241770869589692980),
                GoldilocksField(12148920877529543427),
                GoldilocksField(11483104083757354773),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12463181356489905628),
                GoldilocksField(6403465770372240670),
                GoldilocksField(16425199037094595387),
                GoldilocksField(7978774198302995469),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(890087163658463740),
                GoldilocksField(9141274635664453226),
                GoldilocksField(15224498768632254554),
                GoldilocksField(6695850667011053617),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12495577482299171056),
                GoldilocksField(2605171480627229033),
                GoldilocksField(3018022869204802794),
                GoldilocksField(14000792570659050383),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12472018246019117096),
                GoldilocksField(2043450194934146961),
                GoldilocksField(9189077655089432057),
                GoldilocksField(828034724725175977),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7813414698166985590),
                GoldilocksField(626281170817494273),
                GoldilocksField(2641399934571728819),
                GoldilocksField(11623822558166704213),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9119228065859010667),
                GoldilocksField(13460607379059453275),
                GoldilocksField(1518672983747896134),
                GoldilocksField(4618586691300314275),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11035576819374610396),
                GoldilocksField(3063475597930693282),
                GoldilocksField(6835878216662161885),
                GoldilocksField(2817657244205573760),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(4505670057640567571),
                GoldilocksField(3320598986934358592),
                GoldilocksField(14017573445015955203),
                GoldilocksField(3487622570608276076),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13535396498933471244),
                GoldilocksField(14296409447959912725),
                GoldilocksField(17935267959045248387),
                GoldilocksField(1949429828233945753),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14604468014952023610),
                GoldilocksField(7080451290803913057),
                GoldilocksField(3503129063167967030),
                GoldilocksField(8928047584363180304),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12115660452880790619),
                GoldilocksField(17407443943585186379),
                GoldilocksField(18138034136623502096),
                GoldilocksField(7389033658254830798),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2643590998083957241),
                GoldilocksField(13763412531013400200),
                GoldilocksField(836487056639374932),
                GoldilocksField(6298116150388348051),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14049854916676615000),
                GoldilocksField(13652494560872120417),
                GoldilocksField(16253808402122596919),
                GoldilocksField(10973150678454930354),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6537296600095150713),
                GoldilocksField(9725039621607720650),
                GoldilocksField(12793243189396248553),
                GoldilocksField(3823472010079921644),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6722734251040532646),
                GoldilocksField(14020102803016225303),
                GoldilocksField(8527991650428120963),
                GoldilocksField(9353948522168989777),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17210272454079476781),
                GoldilocksField(3591465778458679498),
                GoldilocksField(18222400727543343124),
                GoldilocksField(1024791459398126465),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13621001815601533835),
                GoldilocksField(10581345568414998953),
                GoldilocksField(8229066275296904566),
                GoldilocksField(3687959274194268509),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6901836896288669132),
                GoldilocksField(6777276837101766124),
                GoldilocksField(2487906248631728433),
                GoldilocksField(6739798134255289300),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5314581944736032537),
                GoldilocksField(14204733617557754030),
                GoldilocksField(6810639103731609163),
                GoldilocksField(12462781458902191355),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(842290605963658897),
                GoldilocksField(3476377273955458754),
                GoldilocksField(8479383567821572957),
                GoldilocksField(7019737985474450360),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(4650843726736957717),
                GoldilocksField(2839751470065996021),
                GoldilocksField(9120775588133625665),
                GoldilocksField(1707083309164077702),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15008801731805054824),
                GoldilocksField(10239030128698075952),
                GoldilocksField(5775276837580167832),
                GoldilocksField(10004386071563770833),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8138537802159657414),
                GoldilocksField(3312905672342561168),
                GoldilocksField(8357322459083296107),
                GoldilocksField(5234034236581808094),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(1523242637077663600),
                GoldilocksField(5045915391449671765),
                GoldilocksField(18151822687114914738),
                GoldilocksField(6458415276081835887),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8071713220461504279),
                GoldilocksField(11243358422517958430),
                GoldilocksField(4604739274076514458),
                GoldilocksField(16233077132562120147),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5732556945450232801),
                GoldilocksField(3612841174606955570),
                GoldilocksField(9098401664260796931),
                GoldilocksField(423708496412405688),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10937578240960695333),
                GoldilocksField(6780841908117854658),
                GoldilocksField(17143248913787823997),
                GoldilocksField(4266058592924500438),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5881053166206773292),
                GoldilocksField(5264670577834284704),
                GoldilocksField(9408393358271421607),
                GoldilocksField(8845101962838951483),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10373324928456409895),
                GoldilocksField(17494121386055086868),
                GoldilocksField(10556416600068297833),
                GoldilocksField(1283020791413913505),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(18227063440207612603),
                GoldilocksField(18125582349103465395),
                GoldilocksField(12580538189059149192),
                GoldilocksField(8971602290657209131),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11321544238884716623),
                GoldilocksField(15428554113238539862),
                GoldilocksField(17455106121934421120),
                GoldilocksField(3271472313598516155),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(550564001223426143),
                GoldilocksField(10802271530213572253),
                GoldilocksField(7783361461191641633),
                GoldilocksField(7502139586411548297),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11835455708027764303),
                GoldilocksField(14578458107799123495),
                GoldilocksField(11337071391761451674),
                GoldilocksField(5976935269377753284),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16302671741632128501),
                GoldilocksField(2146216711599658384),
                GoldilocksField(8758959766293415104),
                GoldilocksField(5740956862165369190),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14790306153291296197),
                GoldilocksField(5373751900160093701),
                GoldilocksField(5512802187424181383),
                GoldilocksField(12664615187750475367),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17348074759284482318),
                GoldilocksField(16142807700592511667),
                GoldilocksField(13648330798506208170),
                GoldilocksField(7566897088561652494),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12094038250237692127),
                GoldilocksField(17139700656931525709),
                GoldilocksField(6495534653318290713),
                GoldilocksField(2464582677765969655),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(18071519622353075825),
                GoldilocksField(15238793814560065741),
                GoldilocksField(5106956307424925000),
                GoldilocksField(1866346203841883945),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16603351681227062680),
                GoldilocksField(12708362643359220537),
                GoldilocksField(9222343917348373521),
                GoldilocksField(3793325270249909101),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9857306238752114726),
                GoldilocksField(1731463585397897050),
                GoldilocksField(9182141530744290977),
                GoldilocksField(18149042099241495455),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7918939713124642057),
                GoldilocksField(1506719714732446346),
                GoldilocksField(10583684562942288000),
                GoldilocksField(4047507868060307026),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9700701010006437924),
                GoldilocksField(1282735553946203251),
                GoldilocksField(14581606274145700807),
                GoldilocksField(5347388978827867753),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6203813396637911013),
                GoldilocksField(11651207448364582891),
                GoldilocksField(15913275739045925927),
                GoldilocksField(9027915310514568080),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(18253829836181233584),
                GoldilocksField(12381169897029668193),
                GoldilocksField(17007400789908290968),
                GoldilocksField(8803018522664603225),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15113472650026691309),
                GoldilocksField(14161346364200041305),
                GoldilocksField(9115136135248965144),
                GoldilocksField(8121545743215784808),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(1227893581897200553),
                GoldilocksField(2906691928576205242),
                GoldilocksField(10362815342685689933),
                GoldilocksField(8633232622627290224),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2783433224165356661),
                GoldilocksField(7070809799159154773),
                GoldilocksField(2471841262790309798),
                GoldilocksField(4497597176010244686),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(3723252026172730715),
                GoldilocksField(5576238488177405789),
                GoldilocksField(11844380762129630216),
                GoldilocksField(13990168898084288124),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16298665427623651402),
                GoldilocksField(4046811304626291257),
                GoldilocksField(12947666410429305589),
                GoldilocksField(14191071318062927033),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(18393834026885153709),
                GoldilocksField(11102001949553963591),
                GoldilocksField(4588267617030160543),
                GoldilocksField(7730725303136959404),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8527887136428692641),
                GoldilocksField(7909039687364321182),
                GoldilocksField(13591882011096126316),
                GoldilocksField(16403688407325697921),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12858107318264956096),
                GoldilocksField(10467438659574850484),
                GoldilocksField(16833686426176495555),
                GoldilocksField(14113359905432118103),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7613432483785584381),
                GoldilocksField(2642396053967468187),
                GoldilocksField(7780306556590617582),
                GoldilocksField(12265437807958003844),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7425609554888514998),
                GoldilocksField(1357204114719411015),
                GoldilocksField(12163564258910217142),
                GoldilocksField(6126439109476934145),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(394880110878840183),
                GoldilocksField(12462216473506620507),
                GoldilocksField(14834407494909932286),
                GoldilocksField(17579782067471662625),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6308385060791524674),
                GoldilocksField(8678584570917687612),
                GoldilocksField(18124539231783733301),
                GoldilocksField(11410207501126941118),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2852268604586796362),
                GoldilocksField(130572270234498881),
                GoldilocksField(2280563504248305148),
                GoldilocksField(17006914713058296575),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9005948377707727693),
                GoldilocksField(13627246296719247452),
                GoldilocksField(5185426521495379801),
                GoldilocksField(13595534017801686977),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(18040263538359895610),
                GoldilocksField(953857654109575370),
                GoldilocksField(13425461349662284507),
                GoldilocksField(7777951613504364529),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7446157859475004514),
                GoldilocksField(1873006133576845324),
                GoldilocksField(17449183274819055371),
                GoldilocksField(6518053628145582811),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9479357211697957423),
                GoldilocksField(16487528426061755253),
                GoldilocksField(256844329302264434),
                GoldilocksField(7853774220179372203),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10931878540810084623),
                GoldilocksField(10493377460165920904),
                GoldilocksField(12490980016430974381),
                GoldilocksField(12687532445952549229),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9571135450078728630),
                GoldilocksField(3053134090271514453),
                GoldilocksField(10941488158081400608),
                GoldilocksField(3136738701223105684),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5681198859759864904),
                GoldilocksField(10677396228451796546),
                GoldilocksField(9519404464341944186),
                GoldilocksField(13492865168778727848),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7120273963133456743),
                GoldilocksField(15746024921099342509),
                GoldilocksField(7723110673611605217),
                GoldilocksField(1149058223255615673),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6271366326794309478),
                GoldilocksField(12581845070518992532),
                GoldilocksField(11154047494909002581),
                GoldilocksField(409306772619740779),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6382667559237479492),
                GoldilocksField(320710445500832073),
                GoldilocksField(16450989473486926603),
                GoldilocksField(5638303253004615711),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(194016765026450878),
                GoldilocksField(16244024714366841815),
                GoldilocksField(7602387756570478716),
                GoldilocksField(16577752616842649226),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(1743426213077107283),
                GoldilocksField(9641043589342460806),
                GoldilocksField(17724611369321782117),
                GoldilocksField(8896825966470039230),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11307450079063224728),
                GoldilocksField(13792219775965215335),
                GoldilocksField(156470175480962572),
                GoldilocksField(8676870026435596901),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15115205659548549579),
                GoldilocksField(4533783102976167723),
                GoldilocksField(10509270907039187165),
                GoldilocksField(13015131193780450049),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12268109409884910500),
                GoldilocksField(8102853407078152303),
                GoldilocksField(14116461276394419306),
                GoldilocksField(13541096506427192130),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2552290571295209072),
                GoldilocksField(17177537346643122264),
                GoldilocksField(16779067096480045764),
                GoldilocksField(5208867680021986871),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12397005261814842898),
                GoldilocksField(15060745503386529218),
                GoldilocksField(4831514493260689350),
                GoldilocksField(12215217066327334793),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9771802784522818770),
                GoldilocksField(10847502751136461498),
                GoldilocksField(9436957940174877188),
                GoldilocksField(16250306370812527333),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12952435611908630792),
                GoldilocksField(9432639106327295009),
                GoldilocksField(17262111961685275196),
                GoldilocksField(8841402896795166560),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11304581182312558597),
                GoldilocksField(14389262123807516969),
                GoldilocksField(7827733251598465297),
                GoldilocksField(13943367012142772194),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10368827838710062453),
                GoldilocksField(3639706274652473488),
                GoldilocksField(17823532077299377329),
                GoldilocksField(13216405116462239947),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(288013795204421440),
                GoldilocksField(6831692327955109429),
                GoldilocksField(18106679015036029153),
                GoldilocksField(3436675918045351917),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8702204117836401540),
                GoldilocksField(3513199115797924550),
                GoldilocksField(3934882910199770967),
                GoldilocksField(12543749194962438235),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11229330975640702356),
                GoldilocksField(10921086350611097143),
                GoldilocksField(9114395432264364214),
                GoldilocksField(14491866877816404264),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13752634502133736869),
                GoldilocksField(8186082100746569409),
                GoldilocksField(9214924906099500672),
                GoldilocksField(8388222932655363003),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7868492169967122886),
                GoldilocksField(615763564216148580),
                GoldilocksField(13149593128801303018),
                GoldilocksField(6467376825220682940),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(3214318842141065975),
                GoldilocksField(9892446350675459929),
                GoldilocksField(10862614609157911760),
                GoldilocksField(16149310342024167691),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(10862366807345544631),
                GoldilocksField(12275692366845967950),
                GoldilocksField(3705323612277887130),
                GoldilocksField(16001091304650171060),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6333644747954732713),
                GoldilocksField(10426510354968678335),
                GoldilocksField(13578546920127023812),
                GoldilocksField(5390237585591433595),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(9782392211750086981),
                GoldilocksField(7430911981804639017),
                GoldilocksField(17564805308702589129),
                GoldilocksField(17237810520755322729),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(348055149181374173),
                GoldilocksField(4154513207246008073),
                GoldilocksField(12952611882506363373),
                GoldilocksField(5922895182876320855),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(1566258506060059910),
                GoldilocksField(12579082001124868397),
                GoldilocksField(8463321206167402748),
                GoldilocksField(10999187857186986230),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8074100836619422449),
                GoldilocksField(842421530830620039),
                GoldilocksField(8648718038407128668),
                GoldilocksField(6466885510810037999),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11437624822638839321),
                GoldilocksField(8320016141102748032),
                GoldilocksField(17543377097896536612),
                GoldilocksField(10937592356138636539),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5989210938037012687),
                GoldilocksField(17874983149138548057),
                GoldilocksField(13758434836834448938),
                GoldilocksField(10283449209494295327),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8399073973985824631),
                GoldilocksField(3668333658433324593),
                GoldilocksField(4382301871669722300),
                GoldilocksField(6687791038854753476),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(1571789333896233106),
                GoldilocksField(15107394143405405516),
                GoldilocksField(5007936928894878787),
                GoldilocksField(15127297772731272045),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8212155396576142297),
                GoldilocksField(10400778476729883738),
                GoldilocksField(1492194672594685652),
                GoldilocksField(1535199356834545887),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(14863160275301160775),
                GoldilocksField(2828801421699834023),
                GoldilocksField(14680821380049739925),
                GoldilocksField(7376090756474160460),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2613788841811500348),
                GoldilocksField(84659195426400317),
                GoldilocksField(2618540168754346507),
                GoldilocksField(247174393952427116),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(5099443906525336056),
                GoldilocksField(5981061235721324341),
                GoldilocksField(15374860908355940353),
                GoldilocksField(6554654220745021684),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6863116245112018304),
                GoldilocksField(11955096780026535598),
                GoldilocksField(4798809106138320436),
                GoldilocksField(17453808603035724856),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(13494373269147343748),
                GoldilocksField(2093471900345455616),
                GoldilocksField(12229349781242216402),
                GoldilocksField(7194241747022116632),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(11314228994503485093),
                GoldilocksField(7948073194268808131),
                GoldilocksField(12330513259899341873),
                GoldilocksField(6103483325295465385),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16053876602230631747),
                GoldilocksField(5100453724073876435),
                GoldilocksField(11843922436173285623),
                GoldilocksField(14666668809862306399),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8662356647955660337),
                GoldilocksField(10540249929136211962),
                GoldilocksField(4389886108147431519),
                GoldilocksField(5447094100611119558),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(3224105324164742693),
                GoldilocksField(14951271246522586002),
                GoldilocksField(9375532522314899206),
                GoldilocksField(8761279993569298561),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(2171066519030172760),
                GoldilocksField(14001526560414108765),
                GoldilocksField(9184806261814505490),
                GoldilocksField(15712598706109227759),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(8093046055188291975),
                GoldilocksField(517455819303374528),
                GoldilocksField(7675760454279316375),
                GoldilocksField(8382698900203508595),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(16911833446425864878),
                GoldilocksField(13714133807990869661),
                GoldilocksField(10468378771482295985),
                GoldilocksField(13919143586272239579),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12059699457765692886),
                GoldilocksField(7060134263277212354),
                GoldilocksField(14543278458683846973),
                GoldilocksField(13344535044643880711),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(12133957381115187709),
                GoldilocksField(8802237464965736469),
                GoldilocksField(6310504651256405245),
                GoldilocksField(5854628497498475035),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(15996988973238993313),
                GoldilocksField(13162149683969500132),
                GoldilocksField(4811768866688164261),
                GoldilocksField(4700487161963525434),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(7279146773460765823),
                GoldilocksField(16392637437038601853),
                GoldilocksField(13158616794083996673),
                GoldilocksField(8922934059029295319),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(17223738911640584909),
                GoldilocksField(10595851197056369423),
                GoldilocksField(12678263981988457575),
                GoldilocksField(6430013388678789320),
            ],
        },
        HashOut {
            elements: [
                GoldilocksField(6021519556190317490),
                GoldilocksField(15360330407788619802),
                GoldilocksField(5108516836807930823),
                GoldilocksField(11391815716172217618),
            ],
        },
    ];
}

impl MerkleZeroHasherWithCache<QHashOut<GoldilocksField>> for PoseidonHasher {
    const CACHED_ZERO_HASHES: [QHashOut<GoldilocksField>; 128] = [
        QHashOut(HashOut {
            elements: [
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(4330397376401421145),
                GoldilocksField(14124799381142128323),
                GoldilocksField(8742572140681234676),
                GoldilocksField(14345658006221440202),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13121882728673923020),
                GoldilocksField(10197653806804742863),
                GoldilocksField(16037207047953124082),
                GoldilocksField(2420399206709257475),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7052649073129349210),
                GoldilocksField(11107139769197583972),
                GoldilocksField(5114845353783771231),
                GoldilocksField(7453521209854829890),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5860469655587923524),
                GoldilocksField(10142584705005652295),
                GoldilocksField(1620588827255328039),
                GoldilocksField(17663938664361140288),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16854358529591173550),
                GoldilocksField(9704301947898025017),
                GoldilocksField(13222045073939169687),
                GoldilocksField(14989445859181028978),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2675805695450374474),
                GoldilocksField(6493392849121218307),
                GoldilocksField(15972287940310989584),
                GoldilocksField(5284431416427098307),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16823738737355150819),
                GoldilocksField(4366876208047374841),
                GoldilocksField(1642083707956929713),
                GoldilocksField(13216064879834397173),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(18334109492892739862),
                GoldilocksField(10192437552951753306),
                GoldilocksField(15211985613247588647),
                GoldilocksField(3157981091968158131),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(4369129498500264270),
                GoldilocksField(10758747855946482846),
                GoldilocksField(3238306058428322199),
                GoldilocksField(18226589090145367109),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14769473886748754115),
                GoldilocksField(10513963056908986963),
                GoldilocksField(8105478726930894327),
                GoldilocksField(14014796621245524545),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10191288259157808067),
                GoldilocksField(944536249556834531),
                GoldilocksField(16268598854718968908),
                GoldilocksField(2417244819673331317),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17088215091100491041),
                GoldilocksField(18086883194773274646),
                GoldilocksField(10296247222913205474),
                GoldilocksField(7017044080942280524),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2985877902215057279),
                GoldilocksField(14516746119572211305),
                GoldilocksField(594952314256159992),
                GoldilocksField(17038984393731825093),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(101510842507023404),
                GoldilocksField(2267676083447667738),
                GoldilocksField(18106248392660779137),
                GoldilocksField(17680390044293740318),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16662284396446084312),
                GoldilocksField(7269926520507830029),
                GoldilocksField(14791338760961128332),
                GoldilocksField(7825163129638412009),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12364052984629808614),
                GoldilocksField(13066500727264825316),
                GoldilocksField(6321076066274078148),
                GoldilocksField(11393071566019822187),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6163084833659416779),
                GoldilocksField(2853393070793212496),
                GoldilocksField(214169662941198197),
                GoldilocksField(766838854721082896),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15062514972738604859),
                GoldilocksField(4072732498117267624),
                GoldilocksField(11453597623878964866),
                GoldilocksField(15196232748141971349),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8105799423402967201),
                GoldilocksField(10398709180756906993),
                GoldilocksField(12579914275816041967),
                GoldilocksField(3722472173064824114),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(4869072528223352863),
                GoldilocksField(6275850450145071959),
                GoldilocksField(8159689720148436485),
                GoldilocksField(8979985763136073723),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8512358054591706621),
                GoldilocksField(12918418052549764713),
                GoldilocksField(3564884046313350424),
                GoldilocksField(18039231110525565261),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10074982884687544941),
                GoldilocksField(4177217016749721471),
                GoldilocksField(4797356481048217516),
                GoldilocksField(6983283665462696061),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7025400382759865156),
                GoldilocksField(2103688473762123306),
                GoldilocksField(8681027323514330807),
                GoldilocksField(13853995481224614401),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(3896366420105793420),
                GoldilocksField(17410332186442776169),
                GoldilocksField(7329967984378645716),
                GoldilocksField(6310665049578686403),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6574146240104132812),
                GoldilocksField(2239043898123515337),
                GoldilocksField(13809601679688051486),
                GoldilocksField(16196448971140258304),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7429917014148897946),
                GoldilocksField(13764740161233226515),
                GoldilocksField(14310941960777962392),
                GoldilocksField(10321132974520710857),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16852763145767657080),
                GoldilocksField(5650551567722662817),
                GoldilocksField(4688637260797538488),
                GoldilocksField(504212361217900660),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17594730245457333136),
                GoldilocksField(13719209718183388763),
                GoldilocksField(11444947689050098668),
                GoldilocksField(628489339233491445),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7731246070744876899),
                GoldilocksField(3033565575746121792),
                GoldilocksField(14735263366152051322),
                GoldilocksField(16212144996433476818),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9947841139978160787),
                GoldilocksField(692236217135079542),
                GoldilocksField(16309341595179079658),
                GoldilocksField(9294006745033445642),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8603459983426387388),
                GoldilocksField(1706773463182378335),
                GoldilocksField(10020230853197995171),
                GoldilocksField(2362856042482390481),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16463394126558395459),
                GoldilocksField(12818610997234032270),
                GoldilocksField(2968763245313636978),
                GoldilocksField(15445927884703223427),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16924929798993045119),
                GoldilocksField(9228476078763095559),
                GoldilocksField(3639599968030750173),
                GoldilocksField(9842693474971302918),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2488667422532942441),
                GoldilocksField(619530082608543022),
                GoldilocksField(3698308124541679027),
                GoldilocksField(1337151890861372088),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10420632113085830027),
                GoldilocksField(2043024317550638523),
                GoldilocksField(9353702824282721936),
                GoldilocksField(13923517817060358740),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2864602688424687291),
                GoldilocksField(3849603923476837883),
                GoldilocksField(15617889861797529219),
                GoldilocksField(12429234418051645329),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2558543962574772915),
                GoldilocksField(9272315342420626056),
                GoldilocksField(4474448392614911585),
                GoldilocksField(1483027055753170828),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15131845414406822716),
                GoldilocksField(5979581984005702075),
                GoldilocksField(6999690762874000865),
                GoldilocksField(9727258862093954055),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16947881275436717432),
                GoldilocksField(7978417559450660789),
                GoldilocksField(5545004785373663100),
                GoldilocksField(8368806924824039910),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7354616297401405606),
                GoldilocksField(1100245580527406969),
                GoldilocksField(10869738626706821039),
                GoldilocksField(2491999729156780167),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6177345289547001265),
                GoldilocksField(16195131218421201680),
                GoldilocksField(8918200175203848893),
                GoldilocksField(9312707430953302559),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15836003362881933006),
                GoldilocksField(11144515108225672409),
                GoldilocksField(11343144721272549260),
                GoldilocksField(4624035188702918165),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15522756684614080517),
                GoldilocksField(13324444309246397554),
                GoldilocksField(17436959028924305779),
                GoldilocksField(18372463735326354528),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7652363938180064696),
                GoldilocksField(4344124640903777315),
                GoldilocksField(13216060880354093579),
                GoldilocksField(13200660336625184843),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(753089390850896872),
                GoldilocksField(12954782300140288288),
                GoldilocksField(5141754559998369457),
                GoldilocksField(16520063853691468679),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16459832343128755954),
                GoldilocksField(10962772927553810074),
                GoldilocksField(6221943911030879674),
                GoldilocksField(17223904123471497456),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17250168555681557323),
                GoldilocksField(2182781226934133394),
                GoldilocksField(18037176460909035824),
                GoldilocksField(14302675719735762512),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11566828016613919825),
                GoldilocksField(8426608301810268318),
                GoldilocksField(12603194638379686261),
                GoldilocksField(12781546638928195534),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11791905468424391494),
                GoldilocksField(353659221674669618),
                GoldilocksField(2954515582080156582),
                GoldilocksField(15617503846144778809),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12046546760594461704),
                GoldilocksField(1281951533681157165),
                GoldilocksField(10510366796594587935),
                GoldilocksField(1585258450210845006),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16107156070019717001),
                GoldilocksField(5384663464106500047),
                GoldilocksField(12860401619817372004),
                GoldilocksField(10797003111418379959),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8380887666379750723),
                GoldilocksField(4340858402662168218),
                GoldilocksField(5588784725350549956),
                GoldilocksField(3717855405583580584),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12350761983522803199),
                GoldilocksField(11629549689432119006),
                GoldilocksField(9356251521583330692),
                GoldilocksField(1763249683801623201),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5953334232381139661),
                GoldilocksField(18330852534639214342),
                GoldilocksField(9077267474540153872),
                GoldilocksField(8746348987390868438),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10539118579154381997),
                GoldilocksField(17127477609463226321),
                GoldilocksField(1631559647739184593),
                GoldilocksField(8422435084782312186),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12731093934649176641),
                GoldilocksField(17896569229540401625),
                GoldilocksField(17267231471603959652),
                GoldilocksField(15919122861351876841),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9216170438539790003),
                GoldilocksField(17899919792125268405),
                GoldilocksField(7770066510145848304),
                GoldilocksField(7399126282406819121),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12999900054714992159),
                GoldilocksField(9111710780146683360),
                GoldilocksField(2059907869783196340),
                GoldilocksField(1375263095716470201),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9229289078495900556),
                GoldilocksField(17561226985028096630),
                GoldilocksField(7202173456809480783),
                GoldilocksField(6438426075407719886),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5180822437522073905),
                GoldilocksField(16008390066609832754),
                GoldilocksField(18037924952145473030),
                GoldilocksField(5507677383726653043),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17083848998177046445),
                GoldilocksField(15548671076670207527),
                GoldilocksField(7110370156869873291),
                GoldilocksField(17694505563696524810),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9905054909759422851),
                GoldilocksField(2256149300669774275),
                GoldilocksField(10823691489106488104),
                GoldilocksField(16995522931301483917),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(4015802642468318748),
                GoldilocksField(6735982660678943841),
                GoldilocksField(17319343432667373419),
                GoldilocksField(3599138393404706899),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10688047713234024277),
                GoldilocksField(9016556671592595466),
                GoldilocksField(6239880553981200190),
                GoldilocksField(251647142305382872),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6105393314971334364),
                GoldilocksField(8496238509745699284),
                GoldilocksField(13056510769289857027),
                GoldilocksField(14070846864809093740),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14445319591693342961),
                GoldilocksField(2101093573226624565),
                GoldilocksField(17138507147001079143),
                GoldilocksField(3073076417314301190),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(3248762874212385128),
                GoldilocksField(2669353020062613412),
                GoldilocksField(15140260944739582298),
                GoldilocksField(18302547056943318452),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13187461470308300539),
                GoldilocksField(5313680972168257602),
                GoldilocksField(14713863290231927335),
                GoldilocksField(8524944837817793747),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6736444608481166433),
                GoldilocksField(2035338806364807431),
                GoldilocksField(1221993307994384273),
                GoldilocksField(15249273592684385399),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15963295117392385071),
                GoldilocksField(17859488035979019650),
                GoldilocksField(16008630532523697014),
                GoldilocksField(14340690071965489891),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15786852763336438198),
                GoldilocksField(10899507674496533139),
                GoldilocksField(11706276358469688200),
                GoldilocksField(14076246040119814704),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13005695680808688691),
                GoldilocksField(14599807539382340192),
                GoldilocksField(9123524395477531261),
                GoldilocksField(3302319617854564490),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12647545642292131518),
                GoldilocksField(13054340139873503226),
                GoldilocksField(4104942492966302442),
                GoldilocksField(14785460214545951374),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12145203032282344677),
                GoldilocksField(5677006333415156410),
                GoldilocksField(14535869388646949163),
                GoldilocksField(11852750114402075515),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11212220522506851472),
                GoldilocksField(17305824071782807976),
                GoldilocksField(13895561172667173499),
                GoldilocksField(10166329586907814359),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15031286889097919562),
                GoldilocksField(1324850860357117632),
                GoldilocksField(10704878335525490727),
                GoldilocksField(6552851480900673495),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7075300658303314337),
                GoldilocksField(7843310150090273296),
                GoldilocksField(10109388471273636642),
                GoldilocksField(2018779330079355536),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7872141395095779165),
                GoldilocksField(5673399122088596117),
                GoldilocksField(15978936760803615870),
                GoldilocksField(10465652434400926706),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(182275601750219224),
                GoldilocksField(2852220150918408331),
                GoldilocksField(4223445253065790943),
                GoldilocksField(12618532050821288848),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6712151225375682294),
                GoldilocksField(5712062620167537207),
                GoldilocksField(17732708101593922837),
                GoldilocksField(6003674375002058874),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17930157576718976452),
                GoldilocksField(7042813770003311174),
                GoldilocksField(10147055593991405452),
                GoldilocksField(16476659124764495938),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10598652526993459074),
                GoldilocksField(12949600898067649801),
                GoldilocksField(6253124184860577720),
                GoldilocksField(8211108850268780660),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2103384426324262455),
                GoldilocksField(12115515654334724875),
                GoldilocksField(12838734626972420570),
                GoldilocksField(16358869782757201076),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2812563820153332707),
                GoldilocksField(17687993387907305983),
                GoldilocksField(6026568395874743064),
                GoldilocksField(11075830002453718343),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2031050619124185341),
                GoldilocksField(1101404102711994941),
                GoldilocksField(13987392891822993041),
                GoldilocksField(14511527341026434685),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5561233035383682398),
                GoldilocksField(8145535878904966949),
                GoldilocksField(5726009330200207924),
                GoldilocksField(5041973692999461630),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7378478920928418813),
                GoldilocksField(240450404700504455),
                GoldilocksField(17177322487057405298),
                GoldilocksField(3235964297969163530),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2631025201140398264),
                GoldilocksField(8739642693994914487),
                GoldilocksField(15983631006751703622),
                GoldilocksField(9271919979380781825),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9078619994338362307),
                GoldilocksField(2144719805640242715),
                GoldilocksField(5949839645737043977),
                GoldilocksField(17987537375692074056),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15703299244758847757),
                GoldilocksField(10237479507707081974),
                GoldilocksField(16159140912123177140),
                GoldilocksField(6916053329562594946),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2008905230162769674),
                GoldilocksField(778563327167966812),
                GoldilocksField(9023142614382901272),
                GoldilocksField(10579687424455663279),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5918609586520646904),
                GoldilocksField(5493709911865566882),
                GoldilocksField(6714426177939800030),
                GoldilocksField(4363038388817350382),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14124154566946968192),
                GoldilocksField(14797837159533557836),
                GoldilocksField(4497323119383238687),
                GoldilocksField(13957527756142492430),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(18213711226300683020),
                GoldilocksField(13754839422409192236),
                GoldilocksField(6119224989292258192),
                GoldilocksField(13243955243086343355),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(4888020708444645063),
                GoldilocksField(8651326230277567641),
                GoldilocksField(10055771106513080840),
                GoldilocksField(9718342223333551334),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6906257647590863271),
                GoldilocksField(5943701417303303045),
                GoldilocksField(4599369487791254927),
                GoldilocksField(2348982053200018605),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(1416509185911772096),
                GoldilocksField(550940063394709840),
                GoldilocksField(6527274302288182846),
                GoldilocksField(16795718617974593),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13567612369227729992),
                GoldilocksField(10937988580152659669),
                GoldilocksField(18136850493928090512),
                GoldilocksField(8498707328026945488),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13555656525371732560),
                GoldilocksField(14981991449200455311),
                GoldilocksField(15427943396918076055),
                GoldilocksField(1655137664584853809),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10317274538960393479),
                GoldilocksField(13936117070735902890),
                GoldilocksField(3289811001287730525),
                GoldilocksField(10355806364261290461),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(1102872660510277355),
                GoldilocksField(2190710156956538771),
                GoldilocksField(14236674262527540226),
                GoldilocksField(14536097873239257103),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10695315653051098334),
                GoldilocksField(8030285986436344422),
                GoldilocksField(15454879862922821727),
                GoldilocksField(2236756262355278575),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14213424163462412247),
                GoldilocksField(6993609101978428580),
                GoldilocksField(13570211413601271193),
                GoldilocksField(1664674736561894083),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9426119267652803899),
                GoldilocksField(5385583849570283439),
                GoldilocksField(8387465646415533185),
                GoldilocksField(4862448025870347107),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14754409489504780682),
                GoldilocksField(3612032561314266125),
                GoldilocksField(17477437432804773001),
                GoldilocksField(445199991733136232),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(3746834526650996498),
                GoldilocksField(12583783367333648152),
                GoldilocksField(1061470622401626801),
                GoldilocksField(2589482137512462630),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13533140977738430832),
                GoldilocksField(10062061273968479833),
                GoldilocksField(9725685130007740348),
                GoldilocksField(16497097183928357178),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13144285485279868119),
                GoldilocksField(4082101042507655201),
                GoldilocksField(12019413233860458726),
                GoldilocksField(3454796547475608022),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13253691564007581919),
                GoldilocksField(1976337399470560924),
                GoldilocksField(16067320056164865996),
                GoldilocksField(17423613029535586111),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10026078945909724048),
                GoldilocksField(1554944974195216216),
                GoldilocksField(11312828219580743432),
                GoldilocksField(15138886657370666864),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16711713583543518975),
                GoldilocksField(13370396718118928879),
                GoldilocksField(13870757116200339751),
                GoldilocksField(4714534636449060433),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13939440524698301346),
                GoldilocksField(8905967259628748834),
                GoldilocksField(13285773279811246083),
                GoldilocksField(5828656143746450870),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7959745668085560084),
                GoldilocksField(11328177091149267320),
                GoldilocksField(17614861725682081647),
                GoldilocksField(6626970770586299947),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12489319969324856588),
                GoldilocksField(2271441446053312817),
                GoldilocksField(15744264430517630150),
                GoldilocksField(18073189248477841368),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5053885937344034804),
                GoldilocksField(10371174610521952640),
                GoldilocksField(3529252918299790231),
                GoldilocksField(9210846005956324247),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13111888119242902725),
                GoldilocksField(11575649969247209511),
                GoldilocksField(14705830568163442720),
                GoldilocksField(16718570455257293963),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10311917907065411495),
                GoldilocksField(9067220426528716341),
                GoldilocksField(6926254564704393288),
                GoldilocksField(2540103339823634721),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(82940137876848047),
                GoldilocksField(4187659877170668778),
                GoldilocksField(11709538958801991737),
                GoldilocksField(8606405806165245200),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(3278897161726127180),
                GoldilocksField(1740841674356247952),
                GoldilocksField(3042306427545138616),
                GoldilocksField(3607849423436667420),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11571301186946206579),
                GoldilocksField(9654002896036126944),
                GoldilocksField(14495186073362022308),
                GoldilocksField(8583768910393503789),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(1753678296021747761),
                GoldilocksField(15625830691687265367),
                GoldilocksField(13394440457762095354),
                GoldilocksField(15442975094580612536),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11049512054443973691),
                GoldilocksField(4951810764889686957),
                GoldilocksField(3253848456007936936),
                GoldilocksField(12251513943682983680),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12776945152172194891),
                GoldilocksField(4657250314707084136),
                GoldilocksField(8866809485494533567),
                GoldilocksField(2718976634788294881),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(3141920725930852063),
                GoldilocksField(1604850316539440905),
                GoldilocksField(7103788112293470972),
                GoldilocksField(1759798822543824539),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5887324832033966576),
                GoldilocksField(15269945251255639671),
                GoldilocksField(10475125945250366169),
                GoldilocksField(4588920059532534839),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17560240928095887948),
                GoldilocksField(339351600890900315),
                GoldilocksField(1590663936866431790),
                GoldilocksField(10818704214216236348),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12859013487963271720),
                GoldilocksField(18068342177185331637),
                GoldilocksField(5027269237729179984),
                GoldilocksField(5564116628722363904),
            ],
        }),
    ];
}

impl MerkleZeroHasherWithCacheMarkedLeaf<QHashOut<GoldilocksField>> for PoseidonHasher {
    const CACHED_MARKED_LEAF_ZERO_HASHES: [QHashOut<GoldilocksField>; 128] = [
        QHashOut(HashOut {
            elements: [
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
                GoldilocksField(0),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6442606111422150320),
                GoldilocksField(5704244332762452547),
                GoldilocksField(4897226532477482799),
                GoldilocksField(12135336437794039610),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(808556306716190912),
                GoldilocksField(2476063296744350509),
                GoldilocksField(15121424568169165254),
                GoldilocksField(3029093053421045263),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12352321749544959065),
                GoldilocksField(5957845988768556333),
                GoldilocksField(15100136569072024617),
                GoldilocksField(16676339421322802800),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11676513847782856690),
                GoldilocksField(11358593067649481162),
                GoldilocksField(9343969531511723369),
                GoldilocksField(16050192720600814849),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7067272467782064710),
                GoldilocksField(1527966539952818982),
                GoldilocksField(8136769675347503390),
                GoldilocksField(4406543573748523830),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(371257336755096171),
                GoldilocksField(12660727904653319748),
                GoldilocksField(13497644411941779497),
                GoldilocksField(18329641640492503964),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17462588609252433262),
                GoldilocksField(6308399974825987705),
                GoldilocksField(11246036879296416044),
                GoldilocksField(1699588579966035392),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10592442612647489306),
                GoldilocksField(13626641172113024814),
                GoldilocksField(5208817656464894676),
                GoldilocksField(10444948860822448724),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(4347348823726450270),
                GoldilocksField(18346478006157677236),
                GoldilocksField(4542629529988803205),
                GoldilocksField(534809824023301308),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9695701940771125402),
                GoldilocksField(10799058527783262173),
                GoldilocksField(6118813008585250486),
                GoldilocksField(8792955908193094753),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9881731838825243287),
                GoldilocksField(10316601684741776174),
                GoldilocksField(15540520434151297193),
                GoldilocksField(13323926745203701243),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7593735662458093260),
                GoldilocksField(17743614875929349477),
                GoldilocksField(2605756623176371665),
                GoldilocksField(6522792836480148337),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13949815761935396135),
                GoldilocksField(7044411766837335933),
                GoldilocksField(3527982556051196377),
                GoldilocksField(6010641661278572926),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13892725284727366476),
                GoldilocksField(14241770869589692980),
                GoldilocksField(12148920877529543427),
                GoldilocksField(11483104083757354773),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12463181356489905628),
                GoldilocksField(6403465770372240670),
                GoldilocksField(16425199037094595387),
                GoldilocksField(7978774198302995469),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(890087163658463740),
                GoldilocksField(9141274635664453226),
                GoldilocksField(15224498768632254554),
                GoldilocksField(6695850667011053617),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12495577482299171056),
                GoldilocksField(2605171480627229033),
                GoldilocksField(3018022869204802794),
                GoldilocksField(14000792570659050383),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12472018246019117096),
                GoldilocksField(2043450194934146961),
                GoldilocksField(9189077655089432057),
                GoldilocksField(828034724725175977),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7813414698166985590),
                GoldilocksField(626281170817494273),
                GoldilocksField(2641399934571728819),
                GoldilocksField(11623822558166704213),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9119228065859010667),
                GoldilocksField(13460607379059453275),
                GoldilocksField(1518672983747896134),
                GoldilocksField(4618586691300314275),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11035576819374610396),
                GoldilocksField(3063475597930693282),
                GoldilocksField(6835878216662161885),
                GoldilocksField(2817657244205573760),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(4505670057640567571),
                GoldilocksField(3320598986934358592),
                GoldilocksField(14017573445015955203),
                GoldilocksField(3487622570608276076),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13535396498933471244),
                GoldilocksField(14296409447959912725),
                GoldilocksField(17935267959045248387),
                GoldilocksField(1949429828233945753),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14604468014952023610),
                GoldilocksField(7080451290803913057),
                GoldilocksField(3503129063167967030),
                GoldilocksField(8928047584363180304),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12115660452880790619),
                GoldilocksField(17407443943585186379),
                GoldilocksField(18138034136623502096),
                GoldilocksField(7389033658254830798),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2643590998083957241),
                GoldilocksField(13763412531013400200),
                GoldilocksField(836487056639374932),
                GoldilocksField(6298116150388348051),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14049854916676615000),
                GoldilocksField(13652494560872120417),
                GoldilocksField(16253808402122596919),
                GoldilocksField(10973150678454930354),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6537296600095150713),
                GoldilocksField(9725039621607720650),
                GoldilocksField(12793243189396248553),
                GoldilocksField(3823472010079921644),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6722734251040532646),
                GoldilocksField(14020102803016225303),
                GoldilocksField(8527991650428120963),
                GoldilocksField(9353948522168989777),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17210272454079476781),
                GoldilocksField(3591465778458679498),
                GoldilocksField(18222400727543343124),
                GoldilocksField(1024791459398126465),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13621001815601533835),
                GoldilocksField(10581345568414998953),
                GoldilocksField(8229066275296904566),
                GoldilocksField(3687959274194268509),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6901836896288669132),
                GoldilocksField(6777276837101766124),
                GoldilocksField(2487906248631728433),
                GoldilocksField(6739798134255289300),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5314581944736032537),
                GoldilocksField(14204733617557754030),
                GoldilocksField(6810639103731609163),
                GoldilocksField(12462781458902191355),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(842290605963658897),
                GoldilocksField(3476377273955458754),
                GoldilocksField(8479383567821572957),
                GoldilocksField(7019737985474450360),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(4650843726736957717),
                GoldilocksField(2839751470065996021),
                GoldilocksField(9120775588133625665),
                GoldilocksField(1707083309164077702),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15008801731805054824),
                GoldilocksField(10239030128698075952),
                GoldilocksField(5775276837580167832),
                GoldilocksField(10004386071563770833),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8138537802159657414),
                GoldilocksField(3312905672342561168),
                GoldilocksField(8357322459083296107),
                GoldilocksField(5234034236581808094),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(1523242637077663600),
                GoldilocksField(5045915391449671765),
                GoldilocksField(18151822687114914738),
                GoldilocksField(6458415276081835887),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8071713220461504279),
                GoldilocksField(11243358422517958430),
                GoldilocksField(4604739274076514458),
                GoldilocksField(16233077132562120147),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5732556945450232801),
                GoldilocksField(3612841174606955570),
                GoldilocksField(9098401664260796931),
                GoldilocksField(423708496412405688),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10937578240960695333),
                GoldilocksField(6780841908117854658),
                GoldilocksField(17143248913787823997),
                GoldilocksField(4266058592924500438),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5881053166206773292),
                GoldilocksField(5264670577834284704),
                GoldilocksField(9408393358271421607),
                GoldilocksField(8845101962838951483),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10373324928456409895),
                GoldilocksField(17494121386055086868),
                GoldilocksField(10556416600068297833),
                GoldilocksField(1283020791413913505),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(18227063440207612603),
                GoldilocksField(18125582349103465395),
                GoldilocksField(12580538189059149192),
                GoldilocksField(8971602290657209131),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11321544238884716623),
                GoldilocksField(15428554113238539862),
                GoldilocksField(17455106121934421120),
                GoldilocksField(3271472313598516155),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(550564001223426143),
                GoldilocksField(10802271530213572253),
                GoldilocksField(7783361461191641633),
                GoldilocksField(7502139586411548297),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11835455708027764303),
                GoldilocksField(14578458107799123495),
                GoldilocksField(11337071391761451674),
                GoldilocksField(5976935269377753284),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16302671741632128501),
                GoldilocksField(2146216711599658384),
                GoldilocksField(8758959766293415104),
                GoldilocksField(5740956862165369190),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14790306153291296197),
                GoldilocksField(5373751900160093701),
                GoldilocksField(5512802187424181383),
                GoldilocksField(12664615187750475367),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17348074759284482318),
                GoldilocksField(16142807700592511667),
                GoldilocksField(13648330798506208170),
                GoldilocksField(7566897088561652494),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12094038250237692127),
                GoldilocksField(17139700656931525709),
                GoldilocksField(6495534653318290713),
                GoldilocksField(2464582677765969655),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(18071519622353075825),
                GoldilocksField(15238793814560065741),
                GoldilocksField(5106956307424925000),
                GoldilocksField(1866346203841883945),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16603351681227062680),
                GoldilocksField(12708362643359220537),
                GoldilocksField(9222343917348373521),
                GoldilocksField(3793325270249909101),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9857306238752114726),
                GoldilocksField(1731463585397897050),
                GoldilocksField(9182141530744290977),
                GoldilocksField(18149042099241495455),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7918939713124642057),
                GoldilocksField(1506719714732446346),
                GoldilocksField(10583684562942288000),
                GoldilocksField(4047507868060307026),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9700701010006437924),
                GoldilocksField(1282735553946203251),
                GoldilocksField(14581606274145700807),
                GoldilocksField(5347388978827867753),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6203813396637911013),
                GoldilocksField(11651207448364582891),
                GoldilocksField(15913275739045925927),
                GoldilocksField(9027915310514568080),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(18253829836181233584),
                GoldilocksField(12381169897029668193),
                GoldilocksField(17007400789908290968),
                GoldilocksField(8803018522664603225),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15113472650026691309),
                GoldilocksField(14161346364200041305),
                GoldilocksField(9115136135248965144),
                GoldilocksField(8121545743215784808),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(1227893581897200553),
                GoldilocksField(2906691928576205242),
                GoldilocksField(10362815342685689933),
                GoldilocksField(8633232622627290224),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2783433224165356661),
                GoldilocksField(7070809799159154773),
                GoldilocksField(2471841262790309798),
                GoldilocksField(4497597176010244686),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(3723252026172730715),
                GoldilocksField(5576238488177405789),
                GoldilocksField(11844380762129630216),
                GoldilocksField(13990168898084288124),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16298665427623651402),
                GoldilocksField(4046811304626291257),
                GoldilocksField(12947666410429305589),
                GoldilocksField(14191071318062927033),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(18393834026885153709),
                GoldilocksField(11102001949553963591),
                GoldilocksField(4588267617030160543),
                GoldilocksField(7730725303136959404),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8527887136428692641),
                GoldilocksField(7909039687364321182),
                GoldilocksField(13591882011096126316),
                GoldilocksField(16403688407325697921),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12858107318264956096),
                GoldilocksField(10467438659574850484),
                GoldilocksField(16833686426176495555),
                GoldilocksField(14113359905432118103),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7613432483785584381),
                GoldilocksField(2642396053967468187),
                GoldilocksField(7780306556590617582),
                GoldilocksField(12265437807958003844),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7425609554888514998),
                GoldilocksField(1357204114719411015),
                GoldilocksField(12163564258910217142),
                GoldilocksField(6126439109476934145),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(394880110878840183),
                GoldilocksField(12462216473506620507),
                GoldilocksField(14834407494909932286),
                GoldilocksField(17579782067471662625),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6308385060791524674),
                GoldilocksField(8678584570917687612),
                GoldilocksField(18124539231783733301),
                GoldilocksField(11410207501126941118),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2852268604586796362),
                GoldilocksField(130572270234498881),
                GoldilocksField(2280563504248305148),
                GoldilocksField(17006914713058296575),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9005948377707727693),
                GoldilocksField(13627246296719247452),
                GoldilocksField(5185426521495379801),
                GoldilocksField(13595534017801686977),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(18040263538359895610),
                GoldilocksField(953857654109575370),
                GoldilocksField(13425461349662284507),
                GoldilocksField(7777951613504364529),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7446157859475004514),
                GoldilocksField(1873006133576845324),
                GoldilocksField(17449183274819055371),
                GoldilocksField(6518053628145582811),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9479357211697957423),
                GoldilocksField(16487528426061755253),
                GoldilocksField(256844329302264434),
                GoldilocksField(7853774220179372203),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10931878540810084623),
                GoldilocksField(10493377460165920904),
                GoldilocksField(12490980016430974381),
                GoldilocksField(12687532445952549229),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9571135450078728630),
                GoldilocksField(3053134090271514453),
                GoldilocksField(10941488158081400608),
                GoldilocksField(3136738701223105684),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5681198859759864904),
                GoldilocksField(10677396228451796546),
                GoldilocksField(9519404464341944186),
                GoldilocksField(13492865168778727848),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7120273963133456743),
                GoldilocksField(15746024921099342509),
                GoldilocksField(7723110673611605217),
                GoldilocksField(1149058223255615673),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6271366326794309478),
                GoldilocksField(12581845070518992532),
                GoldilocksField(11154047494909002581),
                GoldilocksField(409306772619740779),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6382667559237479492),
                GoldilocksField(320710445500832073),
                GoldilocksField(16450989473486926603),
                GoldilocksField(5638303253004615711),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(194016765026450878),
                GoldilocksField(16244024714366841815),
                GoldilocksField(7602387756570478716),
                GoldilocksField(16577752616842649226),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(1743426213077107283),
                GoldilocksField(9641043589342460806),
                GoldilocksField(17724611369321782117),
                GoldilocksField(8896825966470039230),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11307450079063224728),
                GoldilocksField(13792219775965215335),
                GoldilocksField(156470175480962572),
                GoldilocksField(8676870026435596901),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15115205659548549579),
                GoldilocksField(4533783102976167723),
                GoldilocksField(10509270907039187165),
                GoldilocksField(13015131193780450049),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12268109409884910500),
                GoldilocksField(8102853407078152303),
                GoldilocksField(14116461276394419306),
                GoldilocksField(13541096506427192130),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2552290571295209072),
                GoldilocksField(17177537346643122264),
                GoldilocksField(16779067096480045764),
                GoldilocksField(5208867680021986871),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12397005261814842898),
                GoldilocksField(15060745503386529218),
                GoldilocksField(4831514493260689350),
                GoldilocksField(12215217066327334793),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9771802784522818770),
                GoldilocksField(10847502751136461498),
                GoldilocksField(9436957940174877188),
                GoldilocksField(16250306370812527333),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12952435611908630792),
                GoldilocksField(9432639106327295009),
                GoldilocksField(17262111961685275196),
                GoldilocksField(8841402896795166560),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11304581182312558597),
                GoldilocksField(14389262123807516969),
                GoldilocksField(7827733251598465297),
                GoldilocksField(13943367012142772194),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10368827838710062453),
                GoldilocksField(3639706274652473488),
                GoldilocksField(17823532077299377329),
                GoldilocksField(13216405116462239947),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(288013795204421440),
                GoldilocksField(6831692327955109429),
                GoldilocksField(18106679015036029153),
                GoldilocksField(3436675918045351917),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8702204117836401540),
                GoldilocksField(3513199115797924550),
                GoldilocksField(3934882910199770967),
                GoldilocksField(12543749194962438235),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11229330975640702356),
                GoldilocksField(10921086350611097143),
                GoldilocksField(9114395432264364214),
                GoldilocksField(14491866877816404264),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13752634502133736869),
                GoldilocksField(8186082100746569409),
                GoldilocksField(9214924906099500672),
                GoldilocksField(8388222932655363003),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7868492169967122886),
                GoldilocksField(615763564216148580),
                GoldilocksField(13149593128801303018),
                GoldilocksField(6467376825220682940),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(3214318842141065975),
                GoldilocksField(9892446350675459929),
                GoldilocksField(10862614609157911760),
                GoldilocksField(16149310342024167691),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(10862366807345544631),
                GoldilocksField(12275692366845967950),
                GoldilocksField(3705323612277887130),
                GoldilocksField(16001091304650171060),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6333644747954732713),
                GoldilocksField(10426510354968678335),
                GoldilocksField(13578546920127023812),
                GoldilocksField(5390237585591433595),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(9782392211750086981),
                GoldilocksField(7430911981804639017),
                GoldilocksField(17564805308702589129),
                GoldilocksField(17237810520755322729),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(348055149181374173),
                GoldilocksField(4154513207246008073),
                GoldilocksField(12952611882506363373),
                GoldilocksField(5922895182876320855),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(1566258506060059910),
                GoldilocksField(12579082001124868397),
                GoldilocksField(8463321206167402748),
                GoldilocksField(10999187857186986230),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8074100836619422449),
                GoldilocksField(842421530830620039),
                GoldilocksField(8648718038407128668),
                GoldilocksField(6466885510810037999),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11437624822638839321),
                GoldilocksField(8320016141102748032),
                GoldilocksField(17543377097896536612),
                GoldilocksField(10937592356138636539),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5989210938037012687),
                GoldilocksField(17874983149138548057),
                GoldilocksField(13758434836834448938),
                GoldilocksField(10283449209494295327),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8399073973985824631),
                GoldilocksField(3668333658433324593),
                GoldilocksField(4382301871669722300),
                GoldilocksField(6687791038854753476),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(1571789333896233106),
                GoldilocksField(15107394143405405516),
                GoldilocksField(5007936928894878787),
                GoldilocksField(15127297772731272045),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8212155396576142297),
                GoldilocksField(10400778476729883738),
                GoldilocksField(1492194672594685652),
                GoldilocksField(1535199356834545887),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(14863160275301160775),
                GoldilocksField(2828801421699834023),
                GoldilocksField(14680821380049739925),
                GoldilocksField(7376090756474160460),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2613788841811500348),
                GoldilocksField(84659195426400317),
                GoldilocksField(2618540168754346507),
                GoldilocksField(247174393952427116),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(5099443906525336056),
                GoldilocksField(5981061235721324341),
                GoldilocksField(15374860908355940353),
                GoldilocksField(6554654220745021684),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6863116245112018304),
                GoldilocksField(11955096780026535598),
                GoldilocksField(4798809106138320436),
                GoldilocksField(17453808603035724856),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(13494373269147343748),
                GoldilocksField(2093471900345455616),
                GoldilocksField(12229349781242216402),
                GoldilocksField(7194241747022116632),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(11314228994503485093),
                GoldilocksField(7948073194268808131),
                GoldilocksField(12330513259899341873),
                GoldilocksField(6103483325295465385),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16053876602230631747),
                GoldilocksField(5100453724073876435),
                GoldilocksField(11843922436173285623),
                GoldilocksField(14666668809862306399),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8662356647955660337),
                GoldilocksField(10540249929136211962),
                GoldilocksField(4389886108147431519),
                GoldilocksField(5447094100611119558),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(3224105324164742693),
                GoldilocksField(14951271246522586002),
                GoldilocksField(9375532522314899206),
                GoldilocksField(8761279993569298561),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(2171066519030172760),
                GoldilocksField(14001526560414108765),
                GoldilocksField(9184806261814505490),
                GoldilocksField(15712598706109227759),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(8093046055188291975),
                GoldilocksField(517455819303374528),
                GoldilocksField(7675760454279316375),
                GoldilocksField(8382698900203508595),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(16911833446425864878),
                GoldilocksField(13714133807990869661),
                GoldilocksField(10468378771482295985),
                GoldilocksField(13919143586272239579),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12059699457765692886),
                GoldilocksField(7060134263277212354),
                GoldilocksField(14543278458683846973),
                GoldilocksField(13344535044643880711),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(12133957381115187709),
                GoldilocksField(8802237464965736469),
                GoldilocksField(6310504651256405245),
                GoldilocksField(5854628497498475035),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(15996988973238993313),
                GoldilocksField(13162149683969500132),
                GoldilocksField(4811768866688164261),
                GoldilocksField(4700487161963525434),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(7279146773460765823),
                GoldilocksField(16392637437038601853),
                GoldilocksField(13158616794083996673),
                GoldilocksField(8922934059029295319),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(17223738911640584909),
                GoldilocksField(10595851197056369423),
                GoldilocksField(12678263981988457575),
                GoldilocksField(6430013388678789320),
            ],
        }),
        QHashOut(HashOut {
            elements: [
                GoldilocksField(6021519556190317490),
                GoldilocksField(15360330407788619802),
                GoldilocksField(5108516836807930823),
                GoldilocksField(11391815716172217618),
            ],
        }),
    ];
}
