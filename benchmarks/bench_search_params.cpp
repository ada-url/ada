#include "benchmark_header.h"

/**
 * Realistic URL examples collected from Indeed.com, see
 * https://github.com/ada-url/ada/pull/459#issuecomment-1624187633
 */
std::string url_examples_default[] = {
    "https://secure.indeed.com/"
    "auth?continue=https%3A%2F%2Fm5.apply.indeed.com%2Fbeta%2Findeedapply%"
    "2Fresumeapply%3FdraftId%3Dd2f89678-c675-4dd6-8776-c7de2df808cc-Y21o%"
    "26draftDc%3Dcmh%26postUrl%3Dhttp%253A%252F%252Fmuffit%252Fprocess-"
    "indeedapply%26jk%3D4ce8c8f85737012d%26mob%3D0%26referer%3Dhttps%253A%252F%"
    "252Fwww.indeed.com%252F%26formParent%3D%26hl%3Den_US%26jobTitle%"
    "3DEmbedded%2BSoftware%2BEngineer%26questions%3Diq%253A%252F%"
    "252F5a5f158dfd632ec505eb%253Fv%253D1%26twoPaneVjAllocId%3D%"
    "26onappliedstatus%3D_updateIndeedApplyStatus%26preload%3D0%26autoString%"
    "3Dnone%26iip%3D1%26recentsearchquery%3D%257B%2522what%2522%253A%"
    "2522software%2Bengineer%2522%252C%2522where%2522%253A%2522austin%252C%"
    "2Btx%2522%257D%26isCreateIAJobApiSuccess%3Dfalse%26onclose%"
    "3DindeedApplyHandleModalClose%26onContinueClick%"
    "3DindeedApplyHandleModalClose%26jobUrl%3Dhttps%253A%252F%252Fwww.indeed."
    "com%252Fviewjob%253Fjk%253D4ce8c8f85737012d%26onready%3D_onButtonReady%"
    "26onapplied%3DindeedApplyHandleApply%26href%3Dhttps%253A%252F%252Fwww."
    "indeed.com%252Fviewjob%253Fjk%253D4ce8c8f85737012d%2526from%253Dmobhp_"
    "jobfeed_auto%2526tk%253D1h4m9jbiui7lq801%2526viewtype%253Dembedded%"
    "2526advn%253D2919294681304046%2526adid%253D409899006%2526xkcb%253DSoCq-_"
    "M3NWbCoeUCiZ0LbzkdCdPP%2526topwindowlocation%253D%25252F%26coverletter%"
    "3DOPTIONAL%26resume%3Drequired%26twoPaneAllocId%3D%26jobMeta%3D%257B%"
    "2526quot%253Bvtk%2526quot%253B%253A%2526quot%253B1h4m9jddo28q3001%"
    "2526quot%253B%252C%2526quot%253Btk%2526quot%253B%253A%2526quot%"
    "253B1h4m9jbiui7lq801%2526quot%253B%257D%26src%3Didd%26ms%3D1688670424981%"
    "26jobCompany%3DSigmaSense%252C%2BLLC%26onclick%"
    "3DindeedApplyHandleButtonClick%26pingbackUrl%3Dhttps%253A%252F%252Fgdc."
    "indeed.com%252Fconv%252ForgIndApp%253Fco%253DUS%2526vjtk%"
    "253D1h4m9jddo28q3001%2526jk%253D4ce8c8f85737012d%2526mvj%253D0%2526tk%"
    "253D1h4m9jbiui7lq801%2526trk.origin%253Djobsearch%2526sj%253D1%2526vjfrom%"
    "253Dmobhp_jobfeed_auto%2526advn%253D2919294681304046%2526adid%"
    "253D409899006%2526ad%253D-6NYlbfkN0BLmp7eN89U-"
    "imdIS3k1HPy83nFSQVS0CyWSe3vCO57TwIlXkEWIh-"
    "pJhJKr5e0ECbg2AnsbYecK2l6IQRkcmJAo04wMd0HwXw9frAU8JSwJ1mjwcEN4QeCXiILN_"
    "wIA4Wr_ywZCGdozVPXXsoaJzqbyZBeGNAHJQuiHvWOxPzh1LKLSr_"
    "pFbOxn1NmCOkmvvMW36P569CcM6K7a7vOkj32OJUAg8NT_"
    "oipaaUGwXpvKlH6ebfTW6B3WWuJtZ9tsQNwH330zZOVkF1mhjr837W2e-OaEjikG0Nrqh-"
    "9DFBdDUmSLosfcp0hGtARFGYWfp7xU-897-fsivVLte1sPZhzSqWn9P_"
    "D9hHnfmG2LZnTVBp3Jx6QcGng4-U5K8v9KFx7XN9GjcqQum735VDirUpQ61ZT-"
    "WOT5Ilm1xI3nNocOcUQJELhqt6WiAgSIyvTKw7SAfCj2fzp0DshQHzxqVdhe-"
    "iJ9apJI0JWZa195l_ZNFYvu8-rusj79RaBev9_"
    "LPbejUXOZON2MDA37bFHRZsyWNXOCCKl0tswubGZku70sD7HVHm5aYYINKdL_"
    "uKogRuW4r7C99AU69eZMUJF78gl%2526xkcb%253DSoCq-_M3NWbCoeUCiZ0LbzkdCdPP%"
    "2526astse%253Dad9474a7b6ec862d%2526assa%253D8360%26co%3DUS%26advNum%"
    "3D2919294681304046%26noButtonUI%3Dtrue%26iaUid%3D1h4m9je9qjcbf800%26spn%"
    "3D1%26jobId%3D5a5f158dfd632ec505eb%26isITA%3D0%26apiToken%"
    "3Daa102235a5ccb18bd3668c0e14aa3ea7e2503cfac2a7a9bf3d6549899e125af4%"
    "26jobLocation%3DAustin%252C%2BTX%2B78758%26twoPaneGroup%3D-1%"
    "26indeedcsrftoken%3D7bG1QaY6YSlr3rfgMbu9YRVPyk1v2TF0%26phone%3DOPTIONAL%"
    "26jobApplies%3D-1%26twoPaneVjGroup%3D-1%26returnToJobSearchUrl%3Dhttp%"
    "253A%252F%252Fwww.indeed.com%252F%26indeedApplyableJobApiURI%3D&cfb=2&obo="
    "http%3A%2F%2Fwww.indeed.com%2F&hl=en_US&from=indapply-login-SmartApply&"
    "branding=indeed-apply",
    //
    "https://secure.indeed.com/"
    "auth?continue=https%3A%2F%2Fm5.apply.indeed.com%2Fbeta%2Findeedapply%"
    "2Fresumeapply%3FdraftId%3Dcd45b794-ede7-48a2-a143-6023319e90a4-Y21o%"
    "26draftDc%3Dcmh%26postUrl%3Dhttps%253A%252F%252Fapply.workable.com%"
    "252Fapi%252Fv1%252Fjobboards%252Findeed%252Fjobs%252FEC33BF8806%252Fapply%"
    "26jk%3D0ffb6f7ed64d3bae%26mob%3D0%26referer%3Dhttps%253A%252F%252Fwww."
    "indeed.com%252F%26formParent%3D%26hl%3Den_US%26jobTitle%3DEmbedded%"
    "2BSoftware%2BEngineer%26questions%3Dhttps%253A%252F%252Fapply.workable."
    "com%252Fapi%252Fv1%252Fjobboards%252Findeed%252Fjobs%252FEC33BF8806%"
    "252Fquestions%26twoPaneVjAllocId%3D%26onappliedstatus%3D_"
    "updateIndeedApplyStatus%26preload%3D0%26autoString%3Dnone%26iip%3D1%"
    "26recentsearchquery%3D%257B%2522what%2522%253A%2522software%2Bengineer%"
    "2522%252C%2522where%2522%253A%2522austin%252C%2Btx%2522%257D%"
    "26isCreateIAJobApiSuccess%3Dfalse%26onclose%3DindeedApplyHandleModalClose%"
    "26onContinueClick%3DindeedApplyHandleModalClose%26jobUrl%3Dhttps%253A%"
    "252F%252Fwww.indeed.com%252Fviewjob%253Fjk%253D0ffb6f7ed64d3bae%26onready%"
    "3D_onButtonReady%26onapplied%3DindeedApplyHandleApply%26href%3Dhttps%253A%"
    "252F%252Fwww.indeed.com%252Fviewjob%253Fjk%253D0ffb6f7ed64d3bae%2526from%"
    "253Dhp%2526tk%253D1h4m9jbiui7lq801%2526viewtype%253Dembedded%2526advn%"
    "253D2169897021852324%2526adid%253D412530207%2526xkcb%253DSoDv-_"
    "M3NWbCoe0CiZ0LbzkdCdPP%2526topwindowlocation%253D%25252F%26coverletter%3D%"
    "26twoPaneAllocId%3D%26src%3Didd%26ms%3D1688670502027%26jobCompany%3DShift%"
    "2BRobotics%26onclick%3DindeedApplyHandleButtonClick%26pingbackUrl%3Dhttps%"
    "253A%252F%252Fgdc.indeed.com%252Fconv%252ForgIndApp%253Fco%253DUS%"
    "2526vjtk%253D1h4m9ltcgii2t800%2526jk%253D0ffb6f7ed64d3bae%2526mvj%253D0%"
    "2526tk%253D1h4m9jbiui7lq801%2526trk.origin%253Djobsearch%2526sj%253D1%"
    "2526vjfrom%253Dhp%2526advn%253D2169897021852324%2526adid%253D412530207%"
    "2526ad%253D-6NYlbfkN0ADTLHW1lVcttxG1n9WEfcRI1-"
    "ixIWqaQXrnishWQ6BGJjne4HH5OGRzbL9TFjFzxuxk65rhcUupJlJ21QkpPLqd89n0B4cMJw-"
    "xmaYdF9-dzypunDDP4jQEuuhT-tpejJCNc8jlBI6FGBAtkAXuipq96Z-"
    "vOtd24jCWqboqknQBia2fKh5sYbqLv3E7C6vlBmxO2FH4-qm1_"
    "vkeeUq1lsktOtkKCFK2RSR5V5xbkBHcu0hkuZAShjpg2ro3F4e9VbP5_"
    "tC3BKSqdL9un4SibeC59V880-mAhOnU_"
    "yhuURbniZCCFxjEH66D3euJEOSBZDVnpK0jsbAbxwAnx9dtEdC_"
    "HG3BG2PgUf9uwPA8SgdtHuhTAkToYjDBF1l5ENrF3WSXIMTCANToEbE3FpgMwNgOkTDf_"
    "4E0Zf-vZ5LjmNY_8q8gL9SwhL6dAsnb-iH5Nm9OGEI32LTlhl9KtszAFZ99UGlzmRjo_"
    "iD7ienJa3zd_Ebh_NZWkb_4pEKal6--pSAPlVPbC6azvhPiBzQgMhzpUS9Z-7YYhU%25253D%"
    "2526xkcb%253DSoDv-_M3NWbCoe0CiZ0LbzkdCdPP%2526astse%253Dc630be9cfe791df9%"
    "2526assa%253D240%26co%3DUS%26advNum%3D2169897021852324%26noButtonUI%"
    "3Dtrue%26iaUid%3D1h4m9lujpkblm800%26spn%3D1%26jobId%3D5F6DD26C1B%26isITA%"
    "3D0%26apiToken%"
    "3D3a51613a4d8b9799d352130065868b0c34bce36cee7f4dffa3ed16b0c7936634%"
    "26jobLocation%3DAustin%252C%2BTexas%252C%2BUnited%2BStates%26twoPaneGroup%"
    "3D-1%26indeedcsrftoken%3D7bG1QaY6YSlr3rfgMbu9YRVPyk1v2TF0%26phone%"
    "3Doptional%26jobApplies%3D-1%26twoPaneVjGroup%3D-1%26returnToJobSearchUrl%"
    "3Dhttp%253A%252F%252Fwww.indeed.com%252F%26indeedApplyableJobApiURI%3D&"
    "cfb=2&obo=http%3A%2F%2Fwww.indeed.com%2F&hl=en_US&from=indapply-login-"
    "SmartApply&branding=indeed-apply",
    //
    "https://secure.indeed.com/"
    "auth?hl=en_US&co=US&continue=https%3A%2F%2Fwww.indeed.com%"
    "2Fthirdpartysignin%3Fjk%3D67557c870d9debaf%26from%3Dhp%26from%3Djsfe-"
    "3pintercept-viewjob%26tk%3D1h4m9jbiui7lq801%26viewtype%3Dembedded%26advn%"
    "3D8187210054516026%26adid%3D378267801%26ad%3D-6NYlbfkN0CfpH2aSe_"
    "yWN7pjV6WFrWU4hEZi9Btn9eCdDUBIhjK5M5mY81rEexvugfeSup1QuHOvw9d5hvgsJ79xiL2b"
    "Cis9Y8r23bY8qvwxN3cXtMQH5eaPpn4zk1QcFRVOjQFg-"
    "0YX6StKUcjnJroSlWw3vVqor9zKJ4mUJ-Ksql7DBTYyyZGXojbnMo-"
    "neBlW1zDoHnAAl1ZZZa38U8p1jl35T8o9uwhvY3mVw2XDdmKpKawVuyFfiNGl3_"
    "jyLBWarAGLeTBHVsVlBONBK8GK4zH1pVL31V4M43uQUjWUhjRqH4lnq92jt7uCHE97bhKm2hMo"
    "6dpJ6I-"
    "1REKDf9gE0gloVW3r2lBI2TpIWbePg2zuBg4CnvYaRAm7elrbL8hYuiPYtB3hjTkldS_IYH3-"
    "NgunawHQ-"
    "LwIxAO35DyDhaY1DrGuFWaTQj6f1JlddpnImKhUaKP3jgV0q9uKoQxvyyFhLOlLGDxfMsVecGZ"
    "B4lwuUK0TE74Qix1iR26X1QtEguPk8yp8DQZ-AfOqT_"
    "S7A0PtcI2eI0sLM1y3BHB3p0KdpYJUsDv02t7UYO_gNEmMOmcsr5gLsmE-cu52BF_"
    "n2lEDE3kKpIKqMu91dFTmI25H393tb-"
    "PfCUfVAVaUveXuO2hjWSctjtFCo9RPl6ix3ilDs1QgKt08BtT4IUb5I24JlxIJXNvkHhkH75vw"
    "PH9SHKr5XfuN32rOCTUr9JWLmVEcQ4x5A0pHUXQRyz8OxdfsifIibHB8SpDYTtyY50lSL4sAe3"
    "M4PDq0d54xfqWuSQqhGqo0lE944k8JjiQue8M1cIcqpssOOqE8SIi-"
    "hDdv1KG0G1kQuLBIYMzzrGCJ6WDZm_KbLiyK0wTrPf2cWfHIyU1JI1pdWKbK6fop_"
    "kuNd3OBEAl00YETNwOrg4HrZdK8NXEkG_QWXA-A0nYxFWz58uoHND5rkyVDO0o%26xkcb%"
    "3DSoBZ-_M3NWbCoZUCiZ0LbzkdCdPP%26topwindowlocation%3D%252F%253Fadvn%"
    "253D2169897021852324%2526vjk%253D0ffb6f7ed64d3bae%26vjtk%"
    "3D1h4m9npiq21a4002&from=jsfe-3pintercept-viewjob&branding=third-party-"
    "applies",
    //
    "https://secure.indeed.com/"
    "auth?continue=https%3A%2F%2Fm5.apply.indeed.com%2Fbeta%2Findeedapply%"
    "2Fresumeapply%3FdraftId%3Dde4f06da-7b31-465c-96d2-80f791a85bf7-Y21o%"
    "26draftDc%3Dcmh%26postUrl%3Dhttp%253A%252F%252Fmuffit%252Fprocess-"
    "indeedapply%26jk%3D7590bdb1fe928d49%26mob%3D0%26referer%3Dhttps%253A%252F%"
    "252Fwww.indeed.com%252F%253Fvjk%253D4ce8c8f85737012d%2526advn%"
    "253D2919294681304046%26formParent%3D%26hl%3Den_US%26jobTitle%3DSenior%"
    "2BSoftware%2BDeveloper%2B%2528onsite%2529%26questions%3Diq%253A%252F%"
    "252F0efc2325f6b4a2c5bc27%253Fv%253D1%26twoPaneVjAllocId%3D%"
    "26onappliedstatus%3D_updateIndeedApplyStatus%26preload%3D0%26autoString%"
    "3Dnone%26iip%3D1%26recentsearchquery%3D%257B%2522what%2522%253A%"
    "2522software%2Bengineer%2522%252C%2522where%2522%253A%2522austin%252C%"
    "2Btx%2522%257D%26isCreateIAJobApiSuccess%3Dfalse%26onclose%"
    "3DindeedApplyHandleModalClose%26onContinueClick%"
    "3DindeedApplyHandleModalClose%26jobUrl%3Dhttps%253A%252F%252Fwww.indeed."
    "com%252Fviewjob%253Fjk%253D7590bdb1fe928d49%26onready%3D_onButtonReady%"
    "26onapplied%3DindeedApplyHandleApply%26href%3Dhttps%253A%252F%252Fwww."
    "indeed.com%252Fviewjob%253Fjk%253D7590bdb1fe928d49%2526from%253Dhp%2526tk%"
    "253D1h4m9jbiui7lq801%2526viewtype%253Dembedded%2526advn%"
    "253D5522285726153717%2526adid%253D414206073%2526xkcb%253DSoDt-_"
    "M3NWbCoZUCiZ0KbzkdCdPP%2526topwindowlocation%253D%25252F%25253Fvjk%"
    "25253D4ce8c8f85737012d%252526advn%25253D2919294681304046%26coverletter%"
    "3DOPTIONAL%26resume%3Drequired%26twoPaneAllocId%3D%26jobMeta%3D%257B%"
    "2526quot%253Bvtk%2526quot%253B%253A%2526quot%253B1h4m9oh7mirks800%"
    "2526quot%253B%252C%2526quot%253Btk%2526quot%253B%253A%2526quot%"
    "253B1h4m9jbiui7lq801%2526quot%253B%257D%26src%3Didd%26ms%3D1688670587917%"
    "26jobCompany%3DCitizens%2BInc%26onclick%3DindeedApplyHandleButtonClick%"
    "26pingbackUrl%3Dhttps%253A%252F%252Fgdc.indeed.com%252Fconv%252ForgIndApp%"
    "253Fco%253DUS%2526vjtk%253D1h4m9oh7mirks800%2526jk%253D7590bdb1fe928d49%"
    "2526mvj%253D0%2526tk%253D1h4m9jbiui7lq801%2526trk.origin%253Djobsearch%"
    "2526sj%253D1%2526vjfrom%253Dhp%2526advn%253D5522285726153717%2526adid%"
    "253D414206073%2526ad%253D-"
    "6NYlbfkN0CHSAkotDdvvZVbhOqFdbxXOHJMhXe1DXuaBPnaU5fYte-"
    "aud5Z0lqoqFyp33jrJfy1DYFhCWCqBjAqfX3PBXom-d5E4gy3cqbwZuMtWn4flXO-"
    "Fd9DkMZrQjqK002kTnGqvqfkH0ftIspK3hwJPRmAEy7EY87A9OOFRyFmxA9AdiimsdRWyksA-"
    "nCQ0w1VI28XDuVMu7qO_D46dH-"
    "dtW5jWIG4jTe8HCv21447lFobYgFb9oJdF8NrjyCNP4fdGeojlELmcjS5cvC5dKfXi8IZm4sWW"
    "-7b5SBQKvBMmSVDjiTsgYZS6lb8B-"
    "a3YF1Lny7hpNfClmOcLe49wiZAG9LWJ7uRUEfzOPrUCwxdHNQK-vEo3ZhDK4AeER-"
    "LfOUabNSjrKz7_91l8sQjBNOR-FJ25ioX0sqoNByLfJC7cWzjDxqvW-l82GsWQR2O_"
    "6Khe2oq91fjVXMAFQdSQWdr_DWCf_"
    "e2FYtN69Qql9maXH550XNcfynxCicTL71xLstYfWqbSMpADJhrW_"
    "0pf4x58zLVfYLBJ7MPQaW15uKzbFn68lAlyF5GXDqWxowOm58EyeS7OmQkBdGyxYanZ6452m6O"
    "%2526xkcb%253DSoDt-_M3NWbCoZUCiZ0KbzkdCdPP%2526astse%253Db4f6f6ed591bacca%"
    "2526assa%253D6102%26co%3DUS%26advNum%3D5522285726153717%26noButtonUI%"
    "3Dtrue%26iaUid%3D1h4m9oi2qj4h4800%26spn%3D1%26jobId%"
    "3D0efc2325f6b4a2c5bc27%26isITA%3D0%26apiToken%"
    "3Daa102235a5ccb18bd3668c0e14aa3ea7e2503cfac2a7a9bf3d6549899e125af4%"
    "26jobLocation%3DAustin%252C%2BTX%2B78758%26twoPaneGroup%3D-1%"
    "26indeedcsrftoken%3D7bG1QaY6YSlr3rfgMbu9YRVPyk1v2TF0%26phone%3DOPTIONAL%"
    "26jobApplies%3D-1%26twoPaneVjGroup%3D-1%26returnToJobSearchUrl%3Dhttp%"
    "253A%252F%252Fwww.indeed.com%252F%253Fvjk%253D4ce8c8f85737012d%2526advn%"
    "253D2919294681304046%26indeedApplyableJobApiURI%3D&cfb=2&obo=http%3A%2F%"
    "2Fwww.indeed.com%2F&hl=en_US&from=indapply-login-SmartApply&branding="
    "indeed-apply"};

std::vector<std::string> url_examples;

double url_examples_bytes = []() -> double {
  size_t bytes{0};
  for (std::string& url_string : url_examples) {
    bytes += url_string.size();
  }
  return double(bytes);
}();

#ifdef ADA_URL_FILE
const char* default_file = ADA_URL_FILE;
#else
const char* default_file = nullptr;
#endif

size_t init_data(const char* input = default_file) {
  // compute the number of bytes.
  auto compute = []() -> double {
    size_t bytes{0};
    for (std::string& url_string : url_examples) {
      bytes += url_string.size();
    }
    return double(bytes);
  };
  if (input == nullptr) {
    for (const std::string& s : url_examples_default) {
      url_examples.emplace_back(s);
    }
    url_examples_bytes = compute();
    return url_examples.size();
  }

  if (!file_exists(input)) {
    std::cout << "File not found !" << input << std::endl;
    for (const std::string& s : url_examples_default) {
      url_examples.emplace_back(s);
    }
  } else {
    std::cout << "Loading " << input << std::endl;
    url_examples = split_string(read_file(input));
  }
  url_examples_bytes = compute();
  return url_examples.size();
}

size_t count_ada_invalid() {
  size_t how_many = 0;
  for (std::string& url_string : url_examples) {
    auto url = ada::parse(url_string);
    if (!url) {
      how_many++;
    }
  }
  return how_many;
}

template <class result_type = ada::url_aggregator>
static void BasicBench_AdaURL(benchmark::State& state) {
  // volatile to prevent optimizations.
  volatile size_t param_count = 0;

  for (auto _ : state) {
    for (std::string& url_string : url_examples) {
      ada::result<result_type> url = ada::parse<result_type>(url_string);
      if (url) {
        auto params = ada::url_search_params{url->get_search()};
        param_count += params.size();
      }
    }
  }
  if (collector.has_events()) {
    event_aggregate aggregate{};
    for (size_t i = 0; i < N; i++) {
      std::atomic_thread_fence(std::memory_order_acquire);
      collector.start();
      for (std::string& url_string : url_examples) {
        ada::result<result_type> url = ada::parse<result_type>(url_string);
        if (url) {
          auto params = ada::url_search_params{url->get_search()};
          param_count += params.size();
        }
      }
      std::atomic_thread_fence(std::memory_order_release);
      event_count allocate_count = collector.end();
      aggregate << allocate_count;
    }
    state.counters["cycles/url"] =
        aggregate.best.cycles() / std::size(url_examples);
    state.counters["instructions/url"] =
        aggregate.best.instructions() / std::size(url_examples);
    state.counters["instructions/cycle"] =
        aggregate.best.instructions() / aggregate.best.cycles();
    state.counters["instructions/byte"] =
        aggregate.best.instructions() / url_examples_bytes;
    state.counters["instructions/ns"] =
        aggregate.best.instructions() / aggregate.best.elapsed_ns();
    state.counters["GHz"] =
        aggregate.best.cycles() / aggregate.best.elapsed_ns();
    state.counters["ns/url"] =
        aggregate.best.elapsed_ns() / std::size(url_examples);
    state.counters["cycle/byte"] = aggregate.best.cycles() / url_examples_bytes;
  }
  (void)param_count;
  state.counters["time/byte"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate |
                              benchmark::Counter::kInvert);
  state.counters["time/url"] =
      benchmark::Counter(double(std::size(url_examples)),
                         benchmark::Counter::kIsIterationInvariantRate |
                             benchmark::Counter::kInvert);
  state.counters["speed"] = benchmark::Counter(
      url_examples_bytes, benchmark::Counter::kIsIterationInvariantRate);
  state.counters["url/s"] =
      benchmark::Counter(double(std::size(url_examples)),
                         benchmark::Counter::kIsIterationInvariantRate);
}

auto url_search_params_AdaURL = BasicBench_AdaURL<ada::url_aggregator>;
BENCHMARK(url_search_params_AdaURL);

int main(int argc, char** argv) {
  if (argc > 1 && file_exists(argv[1])) {
    init_data(argv[1]);
  } else {
    init_data();
  }
#if (__APPLE__ && __aarch64__) || defined(__linux__)
  if (!collector.has_events()) {
    benchmark::AddCustomContext("performance counters",
                                "No privileged access (sudo may help).");
  }
#else
  if (!collector.has_events()) {
    benchmark::AddCustomContext("performance counters", "Unsupported system.");
  }
#endif
  benchmark::AddCustomContext("input bytes",
                              std::to_string(size_t(url_examples_bytes)));
  benchmark::AddCustomContext("number of URLs",
                              std::to_string(std::size(url_examples)));
  benchmark::AddCustomContext(
      "bytes/URL",
      std::to_string(url_examples_bytes / std::size(url_examples)));
  if (collector.has_events()) {
    benchmark::AddCustomContext("performance counters", "Enabled");
  }
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
}
