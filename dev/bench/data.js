window.BENCHMARK_DATA = {
  "lastUpdate": 1675460119347,
  "repoUrl": "https://github.com/ada-url/ada",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "80479fd3c1aa53dfa2dd67134abde473a9f2d584",
          "message": "fix: normalize (some) of the benchmarks (#184)",
          "timestamp": "2023-01-31T15:50:11-05:00",
          "tree_id": "d7bfae8f32915703dc6c699c9add0a8495905960",
          "url": "https://github.com/ada-url/ada/commit/80479fd3c1aa53dfa2dd67134abde473a9f2d584"
        },
        "date": 1675198294770,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5686.493233913206,
            "unit": "ns/iter",
            "extra": "iterations: 123114\ncpu: 5681.549620676771 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5087.639563618437,
            "unit": "ns/iter",
            "extra": "iterations: 137586\ncpu: 5085.016644135305 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7474.815042613852,
            "unit": "ns/iter",
            "extra": "iterations: 93162\ncpu: 7474.1997810266 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "e05921109c9895a43e2e166a97e040c50c310ead",
          "message": "fix: change the invalid function name for forbidden",
          "timestamp": "2023-01-31T16:42:44-05:00",
          "tree_id": "393a55f56a4dc7f96cb8431c3355bcbd3c7334d7",
          "url": "https://github.com/ada-url/ada/commit/e05921109c9895a43e2e166a97e040c50c310ead"
        },
        "date": 1675201434870,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5586.974346551826,
            "unit": "ns/iter",
            "extra": "iterations: 125909\ncpu: 5560.019537920245 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4966.7905585058825,
            "unit": "ns/iter",
            "extra": "iterations: 141037\ncpu: 4965.177932032021 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7300.743751235734,
            "unit": "ns/iter",
            "extra": "iterations: 96059\ncpu: 7300.091610364466 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "f7f40b0f474396262b91cf9327fb3896084d7301",
          "message": "fix: improve longest sequence finder",
          "timestamp": "2023-01-31T17:22:07-05:00",
          "tree_id": "d9faf6777220a389da9f9b04f6e7a1e4200b8521",
          "url": "https://github.com/ada-url/ada/commit/f7f40b0f474396262b91cf9327fb3896084d7301"
        },
        "date": 1675203799739,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5724.150492711014,
            "unit": "ns/iter",
            "extra": "iterations: 122790\ncpu: 5714.175421451258 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5047.842158705638,
            "unit": "ns/iter",
            "extra": "iterations: 138861\ncpu: 5047.815441340621 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7427.111080412093,
            "unit": "ns/iter",
            "extra": "iterations: 94103\ncpu: 7426.9661966143485 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b93d39c7c9c8bd3753ce335c22d3ae2af81a4b87",
          "message": "fix: Separating the headers so that the inline functions are not messing up the declarations. (#187)\n\n* Separating the headers so that the inline functions are not messing up the declarations.\r\n\r\n* Nope.",
          "timestamp": "2023-01-31T17:22:28-05:00",
          "tree_id": "60455f852a17df31e97d6946e76821d858393f5a",
          "url": "https://github.com/ada-url/ada/commit/b93d39c7c9c8bd3753ce335c22d3ae2af81a4b87"
        },
        "date": 1675203852722,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 6619.065555233762,
            "unit": "ns/iter",
            "extra": "iterations: 107009\ncpu: 6610.265491687616 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5945.917891644002,
            "unit": "ns/iter",
            "extra": "iterations: 117077\ncpu: 5944.143597803155 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 8846.615615767212,
            "unit": "ns/iter",
            "extra": "iterations: 79202\ncpu: 8845.019065175122 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "7545bbfaaa1844fa1c971224bdccca524d1a1c97",
          "message": "Revert \"build: run benchmarks in self-hosted runner\"\n\nThis reverts commit d2a443695bedbca706e886ca6befb213f627fd93.",
          "timestamp": "2023-01-31T18:02:20-05:00",
          "tree_id": "60455f852a17df31e97d6946e76821d858393f5a",
          "url": "https://github.com/ada-url/ada/commit/7545bbfaaa1844fa1c971224bdccca524d1a1c97"
        },
        "date": 1675206191369,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5563.701284506246,
            "unit": "ns/iter",
            "extra": "iterations: 125340\ncpu: 5560.802616882081 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5058.412243224585,
            "unit": "ns/iter",
            "extra": "iterations: 139032\ncpu: 5057.823378790494 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7223.81875097015,
            "unit": "ns/iter",
            "extra": "iterations: 96635\ncpu: 7223.3869715941455 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "4ddd63b4f3a5f6031948d12fc8b18a87e1b0b2c8",
          "message": "Let us be clear what follows what spec.",
          "timestamp": "2023-01-31T18:36:04-05:00",
          "tree_id": "71cba5917231ff2785d9d6eb8509ed7bdda97daf",
          "url": "https://github.com/ada-url/ada/commit/4ddd63b4f3a5f6031948d12fc8b18a87e1b0b2c8"
        },
        "date": 1675208222339,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5514.310466215153,
            "unit": "ns/iter",
            "extra": "iterations: 126980\ncpu: 5508.976216727044 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4989.796376266055,
            "unit": "ns/iter",
            "extra": "iterations: 140794\ncpu: 4989.243859823572 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7250.125677218591,
            "unit": "ns/iter",
            "extra": "iterations: 96350\ncpu: 7244.737934613391 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1e20fae0ee24190627fddf8ea25920c2d0f6ad4e",
          "message": "Adding the url_whatwg library to some benchmarks. (#189)",
          "timestamp": "2023-01-31T20:17:59-05:00",
          "tree_id": "2571270882eca4ee015c32f54d2327b60a5cb278",
          "url": "https://github.com/ada-url/ada/commit/1e20fae0ee24190627fddf8ea25920c2d0f6ad4e"
        },
        "date": 1675214341292,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5617.365567100059,
            "unit": "ns/iter",
            "extra": "iterations: 124352\ncpu: 5616.446860524961 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5065.630833720639,
            "unit": "ns/iter",
            "extra": "iterations: 137648\ncpu: 5065.270835754969 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 11490.357322299538,
            "unit": "ns/iter",
            "extra": "iterations: 60903\ncpu: 11489.690163046158 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7465.736419192011,
            "unit": "ns/iter",
            "extra": "iterations: 94582\ncpu: 7464.421348670996 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "4ae7c7625f596054ff95b345b7b3feac0bd22178",
          "message": "test: add more tests for node.js",
          "timestamp": "2023-02-01T16:38:38-05:00",
          "tree_id": "26a20d6ce8c90e9f9fe5c5ef03ef1d5613ba2a58",
          "url": "https://github.com/ada-url/ada/commit/4ae7c7625f596054ff95b345b7b3feac0bd22178"
        },
        "date": 1675287594267,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5550.845048253529,
            "unit": "ns/iter",
            "extra": "iterations: 125794\ncpu: 5549.321907245178 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4911.865390687006,
            "unit": "ns/iter",
            "extra": "iterations: 142531\ncpu: 4910.957616237872 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 11428.151699702632,
            "unit": "ns/iter",
            "extra": "iterations: 61246\ncpu: 11427.342193775921 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7393.257096157445,
            "unit": "ns/iter",
            "extra": "iterations: 93607\ncpu: 7392.469580266432 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "lemire@gmail.com",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "86e5551a0092c79587fb2b9bda965b76398136c4",
          "message": "We should avoid reserialization if we can cheaply avoid it.",
          "timestamp": "2023-02-01T16:40:06-05:00",
          "tree_id": "e5bbed4a92c5b7f62e2d93302ad8286a24fd6e04",
          "url": "https://github.com/ada-url/ada/commit/86e5551a0092c79587fb2b9bda965b76398136c4"
        },
        "date": 1675287807797,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 7803.667046313168,
            "unit": "ns/iter",
            "extra": "iterations: 91313\ncpu: 7792.823584812679 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 6950.948872718227,
            "unit": "ns/iter",
            "extra": "iterations: 100729\ncpu: 6949.900227342672 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 14828.02852121646,
            "unit": "ns/iter",
            "extra": "iterations: 47228\ncpu: 14826.670619124248 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 10054.708652208112,
            "unit": "ns/iter",
            "extra": "iterations: 69254\ncpu: 10053.85537297485 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "40534d07460ae8e03e5cc1131a7af8a3187cb0c5",
          "message": "docs: update license",
          "timestamp": "2023-02-02T11:56:52-05:00",
          "tree_id": "45db9f60cc59a522ae9cdc3c5cc335423b11e67e",
          "url": "https://github.com/ada-url/ada/commit/40534d07460ae8e03e5cc1131a7af8a3187cb0c5"
        },
        "date": 1675357084578,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5532.317701181968,
            "unit": "ns/iter",
            "extra": "iterations: 126726\ncpu: 5521.126682764389 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4903.892395258661,
            "unit": "ns/iter",
            "extra": "iterations: 142661\ncpu: 4903.294523380602 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 11121.675384590722,
            "unit": "ns/iter",
            "extra": "iterations: 62859\ncpu: 11120.768704561007 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7469.885972976633,
            "unit": "ns/iter",
            "extra": "iterations: 93548\ncpu: 7469.735323042715 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "e67f8f566a2583a5813e63d4862d18ffebe3ae09",
          "message": "Simpler fast path.",
          "timestamp": "2023-02-02T15:22:53-05:00",
          "tree_id": "1e75e1a6435c65b42d1ed5cea771380556df3655",
          "url": "https://github.com/ada-url/ada/commit/e67f8f566a2583a5813e63d4862d18ffebe3ae09"
        },
        "date": 1675369439717,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 6558.639029855596,
            "unit": "ns/iter",
            "extra": "iterations: 106211\ncpu: 6558.380017135702 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5952.399836184676,
            "unit": "ns/iter",
            "extra": "iterations: 118426\ncpu: 5952.235995473968 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 12594.918418310648,
            "unit": "ns/iter",
            "extra": "iterations: 55662\ncpu: 12594.003090079408 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 8714.670925328794,
            "unit": "ns/iter",
            "extra": "iterations: 80620\ncpu: 8713.801786157279 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "5f01757d823fcf4ce8c7f3be52ce45f934cfd3d1",
          "message": "Adding some comments.",
          "timestamp": "2023-02-02T19:35:14-05:00",
          "tree_id": "d6a5e32bee7fd035ebec8a043a6ec3aca08540e2",
          "url": "https://github.com/ada-url/ada/commit/5f01757d823fcf4ce8c7f3be52ce45f934cfd3d1"
        },
        "date": 1675384583302,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5543.414760626768,
            "unit": "ns/iter",
            "extra": "iterations: 126309\ncpu: 5538.5000277098225 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4933.342075393224,
            "unit": "ns/iter",
            "extra": "iterations: 141843\ncpu: 4932.692483943516 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10487.369556089478,
            "unit": "ns/iter",
            "extra": "iterations: 66680\ncpu: 10486.511697660468 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7654.363213241034,
            "unit": "ns/iter",
            "extra": "iterations: 91957\ncpu: 7653.484780930221 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "593668f885ec2ded233cecefa26c93413d1af3fa",
          "message": "feat: Adds a new fast function 'ada::href_from_file'. (#197)\n\n* Adds a new fast function 'ada::href_from_file'.\n\n* Simplifying.\n\n* Removing caching for this runner.\n\n* Fixing runner\n\n* Adding empty new line.\n\n* Removing nodiscard",
          "timestamp": "2023-02-03T15:16:32-05:00",
          "tree_id": "eac4731758ed1450f73355b8e170c66ffee6b2f5",
          "url": "https://github.com/ada-url/ada/commit/593668f885ec2ded233cecefa26c93413d1af3fa"
        },
        "date": 1675455459848,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5555.258017028608,
            "unit": "ns/iter",
            "extra": "iterations: 125670\ncpu: 5554.102808944061 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4985.658462520907,
            "unit": "ns/iter",
            "extra": "iterations: 140945\ncpu: 4971.767710809183 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10682.893654406978,
            "unit": "ns/iter",
            "extra": "iterations: 65447\ncpu: 10682.177945513165 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7480.777093044986,
            "unit": "ns/iter",
            "extra": "iterations: 93954\ncpu: 7466.6719884198665 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "distinct": true,
          "id": "1a4d67aba53c817124d6296c7fee5a8653fd0c3e",
          "message": "Minor fix.",
          "timestamp": "2023-02-03T16:31:41-05:00",
          "tree_id": "d01000c08b66dd35bd4d3b0dfda564479075624e",
          "url": "https://github.com/ada-url/ada/commit/1a4d67aba53c817124d6296c7fee5a8653fd0c3e"
        },
        "date": 1675459972055,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5836.147586378988,
            "unit": "ns/iter",
            "extra": "iterations: 120255\ncpu: 5816.673734979834 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5176.178137022763,
            "unit": "ns/iter",
            "extra": "iterations: 135160\ncpu: 5175.75910032554 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10856.04621953057,
            "unit": "ns/iter",
            "extra": "iterations: 64410\ncpu: 10855.160689333954 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7467.001856677292,
            "unit": "ns/iter",
            "extra": "iterations: 94793\ncpu: 7466.532338885785 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e09e11b6d205e40b5f2d6b13d1623ae3bf04e94e",
          "message": "Update README.md",
          "timestamp": "2023-02-03T16:34:08-05:00",
          "tree_id": "97d9ca7e9bb3f9eead52f820e199e153bb3308c4",
          "url": "https://github.com/ada-url/ada/commit/e09e11b6d205e40b5f2d6b13d1623ae3bf04e94e"
        },
        "date": 1675460107521,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5776.111384853606,
            "unit": "ns/iter",
            "extra": "iterations: 121363\ncpu: 5739.872119179652 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5173.409084883553,
            "unit": "ns/iter",
            "extra": "iterations: 135786\ncpu: 5165.777031505457 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10337.468919859439,
            "unit": "ns/iter",
            "extra": "iterations: 67519\ncpu: 10334.94720004739 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7237.588305365737,
            "unit": "ns/iter",
            "extra": "iterations: 96540\ncpu: 7236.610731303088 ns\nthreads: 1"
          }
        ]
      }
    ],
    "Web Platform Tests": [
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "06751609bf4904a4504ab317ed631fd08582bda5",
          "message": "build: add ccache, competitors and ninja to benchmark",
          "timestamp": "2023-01-31T11:03:56-05:00",
          "tree_id": "9a70561d36e8dcc47107bcf11f691001a68784df",
          "url": "https://github.com/ada-url/ada/commit/06751609bf4904a4504ab317ed631fd08582bda5"
        },
        "date": 1675181159900,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 414969.23885918246,
            "unit": "ns/iter",
            "extra": "iterations: 1683\ncpu: 414943.13725490205 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "4415a26d2d2d5729778010b9afa1f1e008779254",
          "message": "build: keep existing files on documentation deployment",
          "timestamp": "2023-01-31T11:13:11-05:00",
          "tree_id": "c9bf9fda3eb8384b894fc6571dbfdf153e148962",
          "url": "https://github.com/ada-url/ada/commit/4415a26d2d2d5729778010b9afa1f1e008779254"
        },
        "date": 1675181666896,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 557186.0528330752,
            "unit": "ns/iter",
            "extra": "iterations: 1306\ncpu: 555595.1761102603 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "5fe635736da6afe450db334d5a0a573241668d0c",
          "message": "Minor optimization.",
          "timestamp": "2023-01-31T13:29:33-05:00",
          "tree_id": "019df6dcaa86b2d6f8e6eb476b66294ab6d06e95",
          "url": "https://github.com/ada-url/ada/commit/5fe635736da6afe450db334d5a0a573241668d0c"
        },
        "date": 1675189865381,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 499729.54473871936,
            "unit": "ns/iter",
            "extra": "iterations: 1397\ncpu: 499437.7236936293 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bf1cbabdf1c28e8bcaefface7964de44d613ff61",
          "message": "refactor: couple of improvements (#183)",
          "timestamp": "2023-01-31T15:46:53-05:00",
          "tree_id": "1fe91d38f94693f73644aa2f3727926ed63d755d",
          "url": "https://github.com/ada-url/ada/commit/bf1cbabdf1c28e8bcaefface7964de44d613ff61"
        },
        "date": 1675198099661,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 520741.99927954277,
            "unit": "ns/iter",
            "extra": "iterations: 1388\ncpu: 519763.11239193083 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "80479fd3c1aa53dfa2dd67134abde473a9f2d584",
          "message": "fix: normalize (some) of the benchmarks (#184)",
          "timestamp": "2023-01-31T15:50:11-05:00",
          "tree_id": "d7bfae8f32915703dc6c699c9add0a8495905960",
          "url": "https://github.com/ada-url/ada/commit/80479fd3c1aa53dfa2dd67134abde473a9f2d584"
        },
        "date": 1675198298767,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 366594.74631579174,
            "unit": "ns/iter",
            "extra": "iterations: 1900\ncpu: 366567.4210526316 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "e05921109c9895a43e2e166a97e040c50c310ead",
          "message": "fix: change the invalid function name for forbidden",
          "timestamp": "2023-01-31T16:42:44-05:00",
          "tree_id": "393a55f56a4dc7f96cb8431c3355bcbd3c7334d7",
          "url": "https://github.com/ada-url/ada/commit/e05921109c9895a43e2e166a97e040c50c310ead"
        },
        "date": 1675201438526,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 415328.27553444536,
            "unit": "ns/iter",
            "extra": "iterations: 1684\ncpu: 415311.9952494062 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "f7f40b0f474396262b91cf9327fb3896084d7301",
          "message": "fix: improve longest sequence finder",
          "timestamp": "2023-01-31T17:22:07-05:00",
          "tree_id": "d9faf6777220a389da9f9b04f6e7a1e4200b8521",
          "url": "https://github.com/ada-url/ada/commit/f7f40b0f474396262b91cf9327fb3896084d7301"
        },
        "date": 1675203803607,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 368893.419746561,
            "unit": "ns/iter",
            "extra": "iterations: 1894\ncpu: 368579.98944033793 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b93d39c7c9c8bd3753ce335c22d3ae2af81a4b87",
          "message": "fix: Separating the headers so that the inline functions are not messing up the declarations. (#187)\n\n* Separating the headers so that the inline functions are not messing up the declarations.\r\n\r\n* Nope.",
          "timestamp": "2023-01-31T17:22:28-05:00",
          "tree_id": "60455f852a17df31e97d6946e76821d858393f5a",
          "url": "https://github.com/ada-url/ada/commit/b93d39c7c9c8bd3753ce335c22d3ae2af81a4b87"
        },
        "date": 1675203855364,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 505152.85745140817,
            "unit": "ns/iter",
            "extra": "iterations: 1389\ncpu: 503447.01223902096 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "7545bbfaaa1844fa1c971224bdccca524d1a1c97",
          "message": "Revert \"build: run benchmarks in self-hosted runner\"\n\nThis reverts commit d2a443695bedbca706e886ca6befb213f627fd93.",
          "timestamp": "2023-01-31T18:02:20-05:00",
          "tree_id": "60455f852a17df31e97d6946e76821d858393f5a",
          "url": "https://github.com/ada-url/ada/commit/7545bbfaaa1844fa1c971224bdccca524d1a1c97"
        },
        "date": 1675206194179,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 422012.68998793955,
            "unit": "ns/iter",
            "extra": "iterations: 1658\ncpu: 421969.6019300361 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "4ddd63b4f3a5f6031948d12fc8b18a87e1b0b2c8",
          "message": "Let us be clear what follows what spec.",
          "timestamp": "2023-01-31T18:36:04-05:00",
          "tree_id": "71cba5917231ff2785d9d6eb8509ed7bdda97daf",
          "url": "https://github.com/ada-url/ada/commit/4ddd63b4f3a5f6031948d12fc8b18a87e1b0b2c8"
        },
        "date": 1675208225305,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 419150.1677651319,
            "unit": "ns/iter",
            "extra": "iterations: 1669\ncpu: 419099.460754943 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1e20fae0ee24190627fddf8ea25920c2d0f6ad4e",
          "message": "Adding the url_whatwg library to some benchmarks. (#189)",
          "timestamp": "2023-01-31T20:17:59-05:00",
          "tree_id": "2571270882eca4ee015c32f54d2327b60a5cb278",
          "url": "https://github.com/ada-url/ada/commit/1e20fae0ee24190627fddf8ea25920c2d0f6ad4e"
        },
        "date": 1675214346356,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 367440.8256302518,
            "unit": "ns/iter",
            "extra": "iterations: 1904\ncpu: 367399.05462184874 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 434276.23291924765,
            "unit": "ns/iter",
            "extra": "iterations: 1610\ncpu: 434252.36024844734 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "4ae7c7625f596054ff95b345b7b3feac0bd22178",
          "message": "test: add more tests for node.js",
          "timestamp": "2023-02-01T16:38:38-05:00",
          "tree_id": "26a20d6ce8c90e9f9fe5c5ef03ef1d5613ba2a58",
          "url": "https://github.com/ada-url/ada/commit/4ae7c7625f596054ff95b345b7b3feac0bd22178"
        },
        "date": 1675287598243,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 365754.15154691983,
            "unit": "ns/iter",
            "extra": "iterations: 1907\ncpu: 365700.99632931297 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 432917.6672862403,
            "unit": "ns/iter",
            "extra": "iterations: 1614\ncpu: 432860.34696406446 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "lemire@gmail.com",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "86e5551a0092c79587fb2b9bda965b76398136c4",
          "message": "We should avoid reserialization if we can cheaply avoid it.",
          "timestamp": "2023-02-01T16:40:06-05:00",
          "tree_id": "e5bbed4a92c5b7f62e2d93302ad8286a24fd6e04",
          "url": "https://github.com/ada-url/ada/commit/86e5551a0092c79587fb2b9bda965b76398136c4"
        },
        "date": 1675287811301,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 560868.9476896453,
            "unit": "ns/iter",
            "extra": "iterations: 1147\ncpu: 559881.8657367044 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 638862.5273722541,
            "unit": "ns/iter",
            "extra": "iterations: 1096\ncpu: 638823.9051094891 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "40534d07460ae8e03e5cc1131a7af8a3187cb0c5",
          "message": "docs: update license",
          "timestamp": "2023-02-02T11:56:52-05:00",
          "tree_id": "45db9f60cc59a522ae9cdc3c5cc335423b11e67e",
          "url": "https://github.com/ada-url/ada/commit/40534d07460ae8e03e5cc1131a7af8a3187cb0c5"
        },
        "date": 1675357090289,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 374420.51240104483,
            "unit": "ns/iter",
            "extra": "iterations: 1895\ncpu: 368818.62796833774 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 433882.48879203806,
            "unit": "ns/iter",
            "extra": "iterations: 1606\ncpu: 433827.7085927771 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "e67f8f566a2583a5813e63d4862d18ffebe3ae09",
          "message": "Simpler fast path.",
          "timestamp": "2023-02-02T15:22:53-05:00",
          "tree_id": "1e75e1a6435c65b42d1ed5cea771380556df3655",
          "url": "https://github.com/ada-url/ada/commit/e67f8f566a2583a5813e63d4862d18ffebe3ae09"
        },
        "date": 1675369443720,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 500208.89103942405,
            "unit": "ns/iter",
            "extra": "iterations: 1395\ncpu: 500155.3405017922 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 578967.3102880693,
            "unit": "ns/iter",
            "extra": "iterations: 1215\ncpu: 577676.1316872429 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "5f01757d823fcf4ce8c7f3be52ce45f934cfd3d1",
          "message": "Adding some comments.",
          "timestamp": "2023-02-02T19:35:14-05:00",
          "tree_id": "d6a5e32bee7fd035ebec8a043a6ec3aca08540e2",
          "url": "https://github.com/ada-url/ada/commit/5f01757d823fcf4ce8c7f3be52ce45f934cfd3d1"
        },
        "date": 1675384587359,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 369313.9209009854,
            "unit": "ns/iter",
            "extra": "iterations: 1909\ncpu: 368065.26977475116 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 430408.63530134194,
            "unit": "ns/iter",
            "extra": "iterations: 1626\ncpu: 429520.479704797 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "593668f885ec2ded233cecefa26c93413d1af3fa",
          "message": "feat: Adds a new fast function 'ada::href_from_file'. (#197)\n\n* Adds a new fast function 'ada::href_from_file'.\n\n* Simplifying.\n\n* Removing caching for this runner.\n\n* Fixing runner\n\n* Adding empty new line.\n\n* Removing nodiscard",
          "timestamp": "2023-02-03T15:16:32-05:00",
          "tree_id": "eac4731758ed1450f73355b8e170c66ffee6b2f5",
          "url": "https://github.com/ada-url/ada/commit/593668f885ec2ded233cecefa26c93413d1af3fa"
        },
        "date": 1675455463929,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 365537.07304256957,
            "unit": "ns/iter",
            "extra": "iterations: 1903\ncpu: 365488.28166053595 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 437336.04057431483,
            "unit": "ns/iter",
            "extra": "iterations: 1602\ncpu: 437302.7465667916 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "distinct": true,
          "id": "1a4d67aba53c817124d6296c7fee5a8653fd0c3e",
          "message": "Minor fix.",
          "timestamp": "2023-02-03T16:31:41-05:00",
          "tree_id": "d01000c08b66dd35bd4d3b0dfda564479075624e",
          "url": "https://github.com/ada-url/ada/commit/1a4d67aba53c817124d6296c7fee5a8653fd0c3e"
        },
        "date": 1675459977293,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 413063.9863985951,
            "unit": "ns/iter",
            "extra": "iterations: 1691\ncpu: 412951.27143701946 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 436868.1127023707,
            "unit": "ns/iter",
            "extra": "iterations: 1606\ncpu: 436659.9003735991 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e09e11b6d205e40b5f2d6b13d1623ae3bf04e94e",
          "message": "Update README.md",
          "timestamp": "2023-02-03T16:34:08-05:00",
          "tree_id": "97d9ca7e9bb3f9eead52f820e199e153bb3308c4",
          "url": "https://github.com/ada-url/ada/commit/e09e11b6d205e40b5f2d6b13d1623ae3bf04e94e"
        },
        "date": 1675460113447,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 458682.41963110154,
            "unit": "ns/iter",
            "extra": "iterations: 1518\ncpu: 458400.26350461127 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 487631.23955432343,
            "unit": "ns/iter",
            "extra": "iterations: 1436\ncpu: 487583.356545961 ns\nthreads: 1"
          }
        ]
      }
    ],
    "BBC URLs": [
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "80479fd3c1aa53dfa2dd67134abde473a9f2d584",
          "message": "fix: normalize (some) of the benchmarks (#184)",
          "timestamp": "2023-01-31T15:50:11-05:00",
          "tree_id": "d7bfae8f32915703dc6c699c9add0a8495905960",
          "url": "https://github.com/ada-url/ada/commit/80479fd3c1aa53dfa2dd67134abde473a9f2d584"
        },
        "date": 1675198304120,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 4964.06151005605,
            "unit": "ns/iter",
            "extra": "iterations: 141359\ncpu: 4943.8776448616645 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4407.812970171966,
            "unit": "ns/iter",
            "extra": "iterations: 159782\ncpu: 4387.2495024470845 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5789.128373156097,
            "unit": "ns/iter",
            "extra": "iterations: 121622\ncpu: 5788.660768610943 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "e05921109c9895a43e2e166a97e040c50c310ead",
          "message": "fix: change the invalid function name for forbidden",
          "timestamp": "2023-01-31T16:42:44-05:00",
          "tree_id": "393a55f56a4dc7f96cb8431c3355bcbd3c7334d7",
          "url": "https://github.com/ada-url/ada/commit/e05921109c9895a43e2e166a97e040c50c310ead"
        },
        "date": 1675201443066,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5175.749533314557,
            "unit": "ns/iter",
            "extra": "iterations: 136066\ncpu: 5140.942630782121 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4372.83780015863,
            "unit": "ns/iter",
            "extra": "iterations: 159957\ncpu: 4372.316310008316 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5808.509665135126,
            "unit": "ns/iter",
            "extra": "iterations: 120795\ncpu: 5807.880293058491 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "f7f40b0f474396262b91cf9327fb3896084d7301",
          "message": "fix: improve longest sequence finder",
          "timestamp": "2023-01-31T17:22:07-05:00",
          "tree_id": "d9faf6777220a389da9f9b04f6e7a1e4200b8521",
          "url": "https://github.com/ada-url/ada/commit/f7f40b0f474396262b91cf9327fb3896084d7301"
        },
        "date": 1675203808341,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5042.3353321896775,
            "unit": "ns/iter",
            "extra": "iterations: 138746\ncpu: 5040.907845991957 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4397.329471666179,
            "unit": "ns/iter",
            "extra": "iterations: 159085\ncpu: 4396.822453405412 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5845.736861187734,
            "unit": "ns/iter",
            "extra": "iterations: 121358\ncpu: 5807.6261968720655 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "b93d39c7c9c8bd3753ce335c22d3ae2af81a4b87",
          "message": "fix: Separating the headers so that the inline functions are not messing up the declarations. (#187)\n\n* Separating the headers so that the inline functions are not messing up the declarations.\r\n\r\n* Nope.",
          "timestamp": "2023-01-31T17:22:28-05:00",
          "tree_id": "60455f852a17df31e97d6946e76821d858393f5a",
          "url": "https://github.com/ada-url/ada/commit/b93d39c7c9c8bd3753ce335c22d3ae2af81a4b87"
        },
        "date": 1675203859377,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 6363.542909173747,
            "unit": "ns/iter",
            "extra": "iterations: 109825\ncpu: 6361.508763942636 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5243.548915292798,
            "unit": "ns/iter",
            "extra": "iterations: 132893\ncpu: 5242.060153657452 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 6966.110397514273,
            "unit": "ns/iter",
            "extra": "iterations: 101053\ncpu: 6963.901121193828 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "7545bbfaaa1844fa1c971224bdccca524d1a1c97",
          "message": "Revert \"build: run benchmarks in self-hosted runner\"\n\nThis reverts commit d2a443695bedbca706e886ca6befb213f627fd93.",
          "timestamp": "2023-01-31T18:02:20-05:00",
          "tree_id": "60455f852a17df31e97d6946e76821d858393f5a",
          "url": "https://github.com/ada-url/ada/commit/7545bbfaaa1844fa1c971224bdccca524d1a1c97"
        },
        "date": 1675206198305,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5076.989920743696,
            "unit": "ns/iter",
            "extra": "iterations: 137907\ncpu: 5076.629902760556 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4361.5785199623215,
            "unit": "ns/iter",
            "extra": "iterations: 160577\ncpu: 4359.635564246436 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5786.78937606652,
            "unit": "ns/iter",
            "extra": "iterations: 121311\ncpu: 5786.145526786525 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "4ddd63b4f3a5f6031948d12fc8b18a87e1b0b2c8",
          "message": "Let us be clear what follows what spec.",
          "timestamp": "2023-01-31T18:36:04-05:00",
          "tree_id": "71cba5917231ff2785d9d6eb8509ed7bdda97daf",
          "url": "https://github.com/ada-url/ada/commit/4ddd63b4f3a5f6031948d12fc8b18a87e1b0b2c8"
        },
        "date": 1675208229633,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5060.141967227267,
            "unit": "ns/iter",
            "extra": "iterations: 139018\ncpu: 5045.528636579435 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4412.440221634599,
            "unit": "ns/iter",
            "extra": "iterations: 158820\ncpu: 4409.736808966124 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5686.274507094849,
            "unit": "ns/iter",
            "extra": "iterations: 123046\ncpu: 5685.820749963428 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "1e20fae0ee24190627fddf8ea25920c2d0f6ad4e",
          "message": "Adding the url_whatwg library to some benchmarks. (#189)",
          "timestamp": "2023-01-31T20:17:59-05:00",
          "tree_id": "2571270882eca4ee015c32f54d2327b60a5cb278",
          "url": "https://github.com/ada-url/ada/commit/1e20fae0ee24190627fddf8ea25920c2d0f6ad4e"
        },
        "date": 1675214351777,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5116.034864829229,
            "unit": "ns/iter",
            "extra": "iterations: 136642\ncpu: 5109.402672677508 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4544.309959838404,
            "unit": "ns/iter",
            "extra": "iterations: 153878\ncpu: 4543.976396885845 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10503.417162073003,
            "unit": "ns/iter",
            "extra": "iterations: 66612\ncpu: 10503.008466942887 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5767.743240809008,
            "unit": "ns/iter",
            "extra": "iterations: 122130\ncpu: 5767.3421763694405 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "4ae7c7625f596054ff95b345b7b3feac0bd22178",
          "message": "test: add more tests for node.js",
          "timestamp": "2023-02-01T16:38:38-05:00",
          "tree_id": "26a20d6ce8c90e9f9fe5c5ef03ef1d5613ba2a58",
          "url": "https://github.com/ada-url/ada/commit/4ae7c7625f596054ff95b345b7b3feac0bd22178"
        },
        "date": 1675287603187,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5026.716565763714,
            "unit": "ns/iter",
            "extra": "iterations: 139408\ncpu: 5020.862504303914 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4423.923798869983,
            "unit": "ns/iter",
            "extra": "iterations: 158226\ncpu: 4423.649716228686 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10527.260929064632,
            "unit": "ns/iter",
            "extra": "iterations: 66497\ncpu: 10526.742559814731 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5835.43755093221,
            "unit": "ns/iter",
            "extra": "iterations: 120258\ncpu: 5834.841756889354 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "lemire@gmail.com",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "86e5551a0092c79587fb2b9bda965b76398136c4",
          "message": "We should avoid reserialization if we can cheaply avoid it.",
          "timestamp": "2023-02-01T16:40:06-05:00",
          "tree_id": "e5bbed4a92c5b7f62e2d93302ad8286a24fd6e04",
          "url": "https://github.com/ada-url/ada/commit/86e5551a0092c79587fb2b9bda965b76398136c4"
        },
        "date": 1675287816157,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 6955.6005595343595,
            "unit": "ns/iter",
            "extra": "iterations: 95794\ncpu: 6949.686827985052 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 6109.414344202628,
            "unit": "ns/iter",
            "extra": "iterations: 116507\ncpu: 6093.732565425254 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 13696.848293804613,
            "unit": "ns/iter",
            "extra": "iterations: 52661\ncpu: 13694.41712082945 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7819.559673889235,
            "unit": "ns/iter",
            "extra": "iterations: 91380\ncpu: 7817.6263952724885 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "40534d07460ae8e03e5cc1131a7af8a3187cb0c5",
          "message": "docs: update license",
          "timestamp": "2023-02-02T11:56:52-05:00",
          "tree_id": "45db9f60cc59a522ae9cdc3c5cc335423b11e67e",
          "url": "https://github.com/ada-url/ada/commit/40534d07460ae8e03e5cc1131a7af8a3187cb0c5"
        },
        "date": 1675357096158,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5063.065811360034,
            "unit": "ns/iter",
            "extra": "iterations: 138274\ncpu: 5062.409418979707 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4442.60551023654,
            "unit": "ns/iter",
            "extra": "iterations: 157525\ncpu: 4442.43580384066 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10488.399187503457,
            "unit": "ns/iter",
            "extra": "iterations: 66708\ncpu: 10487.854530191287 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5778.193454491477,
            "unit": "ns/iter",
            "extra": "iterations: 121274\ncpu: 5767.95768260303 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "e67f8f566a2583a5813e63d4862d18ffebe3ae09",
          "message": "Simpler fast path.",
          "timestamp": "2023-02-02T15:22:53-05:00",
          "tree_id": "1e75e1a6435c65b42d1ed5cea771380556df3655",
          "url": "https://github.com/ada-url/ada/commit/e67f8f566a2583a5813e63d4862d18ffebe3ae09"
        },
        "date": 1675369448970,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 6125.644375884445,
            "unit": "ns/iter",
            "extra": "iterations: 113769\ncpu: 6124.805526988898 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5293.6091028864075,
            "unit": "ns/iter",
            "extra": "iterations: 132068\ncpu: 5292.690886513007 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 12515.462762253166,
            "unit": "ns/iter",
            "extra": "iterations: 56005\ncpu: 12481.58557271672 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7159.257745497088,
            "unit": "ns/iter",
            "extra": "iterations: 98993\ncpu: 7157.317184043317 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "yagiz@nizipli.com",
            "name": "Yagiz Nizipli",
            "username": "anonrig"
          },
          "distinct": true,
          "id": "5f01757d823fcf4ce8c7f3be52ce45f934cfd3d1",
          "message": "Adding some comments.",
          "timestamp": "2023-02-02T19:35:14-05:00",
          "tree_id": "d6a5e32bee7fd035ebec8a043a6ec3aca08540e2",
          "url": "https://github.com/ada-url/ada/commit/5f01757d823fcf4ce8c7f3be52ce45f934cfd3d1"
        },
        "date": 1675384592225,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5060.3898988879455,
            "unit": "ns/iter",
            "extra": "iterations: 138559\ncpu: 5044.18695285041 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4450.6142585514635,
            "unit": "ns/iter",
            "extra": "iterations: 157253\ncpu: 4450.0079489739455 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10255.508562972764,
            "unit": "ns/iter",
            "extra": "iterations: 68259\ncpu: 10254.471937766446 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5887.793650527003,
            "unit": "ns/iter",
            "extra": "iterations: 119065\ncpu: 5885.710326292358 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "593668f885ec2ded233cecefa26c93413d1af3fa",
          "message": "feat: Adds a new fast function 'ada::href_from_file'. (#197)\n\n* Adds a new fast function 'ada::href_from_file'.\n\n* Simplifying.\n\n* Removing caching for this runner.\n\n* Fixing runner\n\n* Adding empty new line.\n\n* Removing nodiscard",
          "timestamp": "2023-02-03T15:16:32-05:00",
          "tree_id": "eac4731758ed1450f73355b8e170c66ffee6b2f5",
          "url": "https://github.com/ada-url/ada/commit/593668f885ec2ded233cecefa26c93413d1af3fa"
        },
        "date": 1675455468929,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5096.201493619469,
            "unit": "ns/iter",
            "extra": "iterations: 137920\ncpu: 5088.0916473317875 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4466.751382413545,
            "unit": "ns/iter",
            "extra": "iterations: 156791\ncpu: 4466.406235051758 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 9909.089876983608,
            "unit": "ns/iter",
            "extra": "iterations: 70641\ncpu: 9908.186463951528 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5876.245544239389,
            "unit": "ns/iter",
            "extra": "iterations: 119396\ncpu: 5875.880263995444 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "distinct": true,
          "id": "1a4d67aba53c817124d6296c7fee5a8653fd0c3e",
          "message": "Minor fix.",
          "timestamp": "2023-02-03T16:31:41-05:00",
          "tree_id": "d01000c08b66dd35bd4d3b0dfda564479075624e",
          "url": "https://github.com/ada-url/ada/commit/1a4d67aba53c817124d6296c7fee5a8653fd0c3e"
        },
        "date": 1675459982908,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5188.976638710551,
            "unit": "ns/iter",
            "extra": "iterations: 134496\ncpu: 5185.612955032121 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4623.4247886468675,
            "unit": "ns/iter",
            "extra": "iterations: 151287\ncpu: 4622.737578245322 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10048.337392426885,
            "unit": "ns/iter",
            "extra": "iterations: 69720\ncpu: 10047.758175559382 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5825.53790071719,
            "unit": "ns/iter",
            "extra": "iterations: 120565\ncpu: 5815.422386264669 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "daniel@lemire.me",
            "name": "Daniel Lemire",
            "username": "lemire"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "e09e11b6d205e40b5f2d6b13d1623ae3bf04e94e",
          "message": "Update README.md",
          "timestamp": "2023-02-03T16:34:08-05:00",
          "tree_id": "97d9ca7e9bb3f9eead52f820e199e153bb3308c4",
          "url": "https://github.com/ada-url/ada/commit/e09e11b6d205e40b5f2d6b13d1623ae3bf04e94e"
        },
        "date": 1675460118795,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5301.8111701520165,
            "unit": "ns/iter",
            "extra": "iterations: 131547\ncpu: 5289.837092446046 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4697.737237943081,
            "unit": "ns/iter",
            "extra": "iterations: 148918\ncpu: 4696.408090358453 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 9724.57491716114,
            "unit": "ns/iter",
            "extra": "iterations: 71826\ncpu: 9716.949294127477 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5866.584125200036,
            "unit": "ns/iter",
            "extra": "iterations: 117444\ncpu: 5864.672524777769 ns\nthreads: 1"
          }
        ]
      }
    ]
  }
}