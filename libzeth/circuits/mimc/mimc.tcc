// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_CIRCUITS_MIMC_TCC__
#define __ZETH_CIRCUITS_MIMC_TCC__

#include "libzeth/circuits/mimc/mimc.hpp"

namespace libzeth
{

template<typename FieldT, size_t Exponent, size_t NumRounds>
std::vector<FieldT>
    MiMC_permutation_gadget<FieldT, Exponent, NumRounds>::_round_constants;

template<typename FieldT, size_t Exponent, size_t NumRounds>
bool MiMC_permutation_gadget<FieldT, Exponent, NumRounds>::
    _round_constants_initialized = false;

template<typename FieldT, size_t Exponent, size_t NumRounds>
MiMC_permutation_gadget<FieldT, Exponent, NumRounds>::MiMC_permutation_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &msg,
    const libsnark::pb_variable<FieldT> &key,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), _key(key)
{
    // First we initialize the round constants
    setup_sha3_constants();

    // Then we initialize the round gadgets
    setup_gadgets(msg, key);
}

template<typename FieldT, size_t Exponent, size_t NumRounds>
void MiMC_permutation_gadget<FieldT, Exponent, NumRounds>::
    generate_r1cs_constraints()
{
    // For each round, generates the constraints for the corresponding round
    // gadget
    for (auto &gadget : _round_gadgets) {
        gadget.generate_r1cs_constraints();
    }
}

template<typename FieldT, size_t Exponent, size_t NumRounds>
void MiMC_permutation_gadget<FieldT, Exponent, NumRounds>::
    generate_r1cs_witness() const
{
    // For each round, generates the witness for the corresponding round gadget
    for (auto &gadget : _round_gadgets) {
        gadget.generate_r1cs_witness();
    }
}

template<typename FieldT, size_t Exponent, size_t NumRounds>
const libsnark::pb_variable<FieldT>
    &MiMC_permutation_gadget<FieldT, Exponent, NumRounds>::result() const
{
    // Returns the result of the last encryption/permutation
    return _round_results.back();
}

template<typename FieldT, size_t Exponent, size_t NumRounds>
void MiMC_permutation_gadget<FieldT, Exponent, NumRounds>::setup_gadgets(
    const libsnark::pb_variable<FieldT> &msg,
    const libsnark::pb_variable<FieldT> &key)
{
    _round_gadgets.reserve(NumRounds);
    const libsnark::pb_variable<FieldT> *round_x = &msg;
    for (size_t i = 0; i < NumRounds; i++) {
        // Set the input of the next round with the output variable of the
        // previous round (except for round 0)
        _round_results[i].allocate(
            this->pb, FMT(this->annotation_prefix, " round_result[%zu]", i));

        const bool is_last = (i == (NumRounds - 1));

        // Initialize and add the current round gadget into the rounds gadget
        // vector, picking the relative constant
        _round_gadgets.emplace_back(
            this->pb,
            *round_x,
            key,
            _round_constants[i],
            _round_results[i],
            is_last,
            FMT(this->annotation_prefix, " round[%zu]", i));

        round_x = &_round_results[i];
    }
}

// The following constants correspond to the iterative computation of sha3_256
// hash function over the initial seed "clearmatics_mt_seed". See:
// client/zethCodeConstantsGeneration.py for more details
template<typename FieldT, size_t Exponent, size_t NumRounds>
void MiMC_permutation_gadget<FieldT, Exponent, NumRounds>::
    setup_sha3_constants()
{
    if (_round_constants_initialized) {
        return;
    }

    _round_constants.reserve(NumRounds);

    // The constant is set to "0" in the first round of MiMC permutation (see:
    // https://eprint.iacr.org/2016/492.pdf)
    _round_constants.push_back(FieldT("0"));

    // clang-format off

    // This is sha3_256(sha3_256("clearmatics_mt_seed"))
    _round_constants.push_back(FieldT(
        "22159019873790129476324495190496603411493310235845550845393361088354059025587"));

    _round_constants.push_back(FieldT(
        "27761654615899466766976328798614662221520122127418767386594587425934055859027"));
    _round_constants.push_back(FieldT(
        "94824950344308939111646914673652476426466554475739520071212351703914847519222"));
    _round_constants.push_back(FieldT(
        "84875755167904490740680810908425347913240786521935721949482414218097022905238"));
    _round_constants.push_back(FieldT(
        "103827469404022738626089808362855974444473512881791722903435218437949312500276"));
    _round_constants.push_back(FieldT(
        "79151333313630310680682684119244096199179603958178503155035988149812024220238"));
    _round_constants.push_back(FieldT(
        "69032546029442066350494866745598303896748709048209836077355812616627437932521"));
    _round_constants.push_back(FieldT(
        "71828934229806034323678289655618358926823037947843672773514515549250200395747"));
    _round_constants.push_back(FieldT(
        "20380360065304068228640594346624360147706079921816528167847416754157399404427"));
    _round_constants.push_back(FieldT(
        "33389882590456326015242966586990383840423378222877476683761799984554709177407"));
    _round_constants.push_back(FieldT(
        "50122810070778420844700285367936543284029126632619100118638682958218725318756"));
    _round_constants.push_back(FieldT(
        "49246859699528342369154520789249265070136349803358469088610922925489948122588"));
    _round_constants.push_back(FieldT(
        "42301293999667742503298132605205313473294493780037112351216393454277775233701"));
    _round_constants.push_back(FieldT(
        "84114918321547685007627041787929288135785026882582963701427252073231899729239"));
    _round_constants.push_back(FieldT(
        "62442564517333183431281494169332072638102772915973556148439397377116238052032"));
    _round_constants.push_back(FieldT(
        "90371696767943970492795296318744142024828099537644566050263944542077360454000"));
    _round_constants.push_back(FieldT(
        "115430938798103259020685569971731347341632428718094375123887258419895353452385"));
    _round_constants.push_back(FieldT(
        "113486567655643015051612432235944767094037016028918659325405959747202187788641"));
    _round_constants.push_back(FieldT(
        "42521224046978113548086179860571260859679910353297292895277062016640527060158"));
    _round_constants.push_back(FieldT(
        "59337418021535832349738836949730504849571827921681387254433920345654363097721"));
    _round_constants.push_back(FieldT(
        "11312792726948192147047500338922194498305047686482578113645836215734847502787"));
    _round_constants.push_back(FieldT(
        "5531104903388534443968883334496754098135862809700301013033503341381689618972"));
    _round_constants.push_back(FieldT(
        "67267967506593457603372921446668397713655666818276613345969561709158934132467"));
    _round_constants.push_back(FieldT(
        "14150601882795046585170507190892504128795190437985555320824531798948976631295"));
    _round_constants.push_back(FieldT(
        "85062650450907709431728516509140931676564801299509460081586249478375415684322"));
    _round_constants.push_back(FieldT(
        "3190636703526705373452173482292964566521687248139217048214149162895182633187"));
    _round_constants.push_back(FieldT(
        "94697707246459731032848302079578714910941380385884087153796554334872238022178"));
    _round_constants.push_back(FieldT(
        "105237079024348272465679804525604310926083869213267017956044692586513087552889"));
    _round_constants.push_back(FieldT(
        "107666297462370279081061498341391155289817553443536637437225808625028106164694"));
    _round_constants.push_back(FieldT(
        "50658185643016152702409617752847261961811370146977869351531768522548888496960"));
    _round_constants.push_back(FieldT(
        "40194505239242861003888376856216043830225436269588275639840138989648733836164"));
    _round_constants.push_back(FieldT(
        "18446023938001439123322925291203176968088321100216399802351969471087090508798"));
    _round_constants.push_back(FieldT(
        "56716868411561319312404565555682857409226456576794830238428782927207680423406"));
    _round_constants.push_back(FieldT(
        "99446603622401702299467002115709680008186357666919726252089514718382895122907"));
    _round_constants.push_back(FieldT(
        "14440268383603206763216449941954085575335212955165966039078057319953582173633"));
    _round_constants.push_back(FieldT(
        "19800531992512132732080265836821627955799468140051158794892004229352040429024"));
    _round_constants.push_back(FieldT(
        "105297016338495372394147178784104774655759157445835217996114870903812070518445"));
    _round_constants.push_back(FieldT(
        "25603899274511343521079846952994517772529013612481201245155078199291999403355"));
    _round_constants.push_back(FieldT(
        "42343992762533961606462320250264898254257373842674711124109812370529823212221"));
    _round_constants.push_back(FieldT(
        "10746157796797737664081586165620034657529089112211072426663365617141344936203"));
    _round_constants.push_back(FieldT(
        "83415911130754382252267592583976834889211427666721691843694426391396310581540"));
    _round_constants.push_back(FieldT(
        "90866605176883156213219983011392724070678633758652939051248987072469444200627"));
    _round_constants.push_back(FieldT(
        "37024565646714391930474489137778856553925761915366252060067939966442059957164"));
    _round_constants.push_back(FieldT(
        "7989471243134634308962365261048299254340659799910534445820512869869542788064"));
    _round_constants.push_back(FieldT(
        "15648939481289140348738679797715724220399212972574021006219862339465296839884"));
    _round_constants.push_back(FieldT(
        "100133438935846292803417679717817950677446943844926655798697284495340753961844"));
    _round_constants.push_back(FieldT(
        "84618212755822467879717121296483255659772850854170590780922087915497421596465"));
    _round_constants.push_back(FieldT(
        "66815981435852782130184794409662156021404245655267602728283138458689925010111"));
    _round_constants.push_back(FieldT(
        "100011403138602452635630699813302791324969902443516593676764382923531277739340"));
    _round_constants.push_back(FieldT(
        "57430361797750645341842394309545159343198597441951985629580530284393758413106"));
    _round_constants.push_back(FieldT(
        "70240009849732555205629614425470918637568887938810907663457802670777054165279"));
    _round_constants.push_back(FieldT(
        "115341201140672997375646566164431266507025151688875346248495663683620086806942"));
    _round_constants.push_back(FieldT(
        "11188962021222070760150833399355814187143871338754315850627637681691407594017"));
    _round_constants.push_back(FieldT(
        "22685520879254273934490401340849316430229408194604166253482138215686716109430"));
    _round_constants.push_back(FieldT(
        "51189210546148312327463530170430162293845070064001770900624850430825589457055"));
    _round_constants.push_back(FieldT(
        "14807565813027010873011142172745696288480075052292277459306275231121767039664"));
    _round_constants.push_back(FieldT(
        "95539138374056424883213912295679274059417180869462186511207318536449091576661"));
    _round_constants.push_back(FieldT(
        "113489397464329757187555603731541774715600099685729291423921796997078292946609"));
    _round_constants.push_back(FieldT(
        "104312240868162447193722372229442001535106018532365202206691174960555358414880"));
    _round_constants.push_back(FieldT(
        "8267151326618998101166373872748168146937148303027773815001564349496401227343"));
    _round_constants.push_back(FieldT(
        "76298755107890528830128895628139521831584444593650120338808262678169950673284"));
    _round_constants.push_back(FieldT(
        "73002305935054160156217464153178860593131914821282451210510325210791458847694"));
    _round_constants.push_back(FieldT(
        "74544443080560119509560262720937836494902079641131221139823065933367514898276"));
    _round_constants.push_back(FieldT(
        "36856043990250139109110674451326757800006928098085552406998173198427373834846"));
    _round_constants.push_back(FieldT(
        "89876265522016337550524744707009312276376790319197860491657618155961055194949"));
    _round_constants.push_back(FieldT(
        "110827903006446644954303964609043521818500007209339765337677716791359271709709"));
    _round_constants.push_back(FieldT(
        "19507166101303357762640682204614541813131172968402646378144792525256753001746"));
    _round_constants.push_back(FieldT(
        "107253144238416209039771223682727408821599541893659793703045486397265233272366"));
    _round_constants.push_back(FieldT(
        "50595349797145823467207046063156205987118773849740473190540000392074846997926"));
    _round_constants.push_back(FieldT(
        "44703482889665897122601827877356260454752336134846793080442136212838463818460"));
    _round_constants.push_back(FieldT(
        "72587689163044446617379334085046687704026377073069181869522598220420039333904"));
    _round_constants.push_back(FieldT(
        "102651401786920090371975453907921346781687924794638352783098945209363379010084"));
    _round_constants.push_back(FieldT(
        "93452870373806728605513560063145330258676656934938716540885043830342716774537"));
    _round_constants.push_back(FieldT(
        "78296669596559313198894751403351590225284664485458045241864014863714864424243"));
    _round_constants.push_back(FieldT(
        "115089219682233450926699488628267277641700041858332325616476033644461392438459"));
    _round_constants.push_back(FieldT(
        "12503229023709380637667243769419362848195673442247523096260626221166887267863"));
    _round_constants.push_back(FieldT(
        "4710254915107472945023322521703570589554948344762175784852248799008742965033"));
    _round_constants.push_back(FieldT(
        "7718237385336937042064321465151951780913850666971695410931421653062451982185"));
    _round_constants.push_back(FieldT(
        "115218487714637830492048339157964615618803212766527542809597433013530253995292"));
    _round_constants.push_back(FieldT(
        "30146276054995781136885926012526705051587400199196161599789168368938819073525"));
    _round_constants.push_back(FieldT(
        "81645575619063610562025782726266715757461113967190574155696199274188206173145"));
    _round_constants.push_back(FieldT(
        "103065286526250765895346723898189993161715212663393551904337911885906019058491"));
    _round_constants.push_back(FieldT(
        "19401253163389218637767300383887292725233192135251696535631823232537040754970"));
    _round_constants.push_back(FieldT(
        "39843332085422732827481601668576197174769872102167705377474553046529879993254"));
    _round_constants.push_back(FieldT(
        "27288628349107331632228897768386713717171618488175838305048363657709955104492"));
    _round_constants.push_back(FieldT(
        "63512042813079522866974560192099016266996589861590638571563519363305976473166"));
    _round_constants.push_back(FieldT(
        "88099896769123586138541398153669061847681467623298355942484821247745931328016"));
    _round_constants.push_back(FieldT(
        "69497565113721491657291572438744729276644895517335084478398926389231201598482"));
    _round_constants.push_back(FieldT(
        "17118586436782638926114048491697362406660860405685472757612739816905521144705"));
    _round_constants.push_back(FieldT(
        "50507769484714413215987736701379019852081133212073163694059431350432441698257"));
    // clang-format on

    _round_constants_initialized = true;
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_MIMC_TCC__
