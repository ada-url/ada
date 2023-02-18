window.BENCHMARK_DATA = {
  "lastUpdate": 1676737768823,
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
          "id": "487c098557bbafa5953d12adbd224e7d7205cffd",
          "message": "Update README.md",
          "timestamp": "2023-02-03T16:36:02-05:00",
          "tree_id": "cca2d4c6a8643401588b68dda927765e9bf3a0cd",
          "url": "https://github.com/ada-url/ada/commit/487c098557bbafa5953d12adbd224e7d7205cffd"
        },
        "date": 1675460212213,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5853.388487332066,
            "unit": "ns/iter",
            "extra": "iterations: 118843\ncpu: 5852.206692863694 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5209.575353463316,
            "unit": "ns/iter",
            "extra": "iterations: 134526\ncpu: 5208.41844699166 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10835.900210800684,
            "unit": "ns/iter",
            "extra": "iterations: 64516\ncpu: 10835.837621675242 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7480.218019576407,
            "unit": "ns/iter",
            "extra": "iterations: 94808\ncpu: 7479.781242089274 ns\nthreads: 1"
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
          "id": "a1c32a52c293ff17f329c5e561f2467c51ea69a3",
          "message": "docs: update namespace definitions",
          "timestamp": "2023-02-03T17:01:28-05:00",
          "tree_id": "e74bd9e20da14bee13297bab5ddc56aeb15d90b4",
          "url": "https://github.com/ada-url/ada/commit/a1c32a52c293ff17f329c5e561f2467c51ea69a3"
        },
        "date": 1675461763944,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5869.858068384381,
            "unit": "ns/iter",
            "extra": "iterations: 120086\ncpu: 5820.920007328082 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5157.574167902049,
            "unit": "ns/iter",
            "extra": "iterations: 135591\ncpu: 5147.829870714132 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10384.310637097888,
            "unit": "ns/iter",
            "extra": "iterations: 67368\ncpu: 10376.422040137755 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7332.7994763849165,
            "unit": "ns/iter",
            "extra": "iterations: 95490\ncpu: 7332.056759870141 ns\nthreads: 1"
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
          "id": "4c76670329ad2bd2b1c7f9541b2faee923086438",
          "message": "build: add singleheader files to gitignore",
          "timestamp": "2023-02-04T12:01:29-05:00",
          "tree_id": "061cb04be2908dcba5a3d204eab85c46628c0e0c",
          "url": "https://github.com/ada-url/ada/commit/4c76670329ad2bd2b1c7f9541b2faee923086438"
        },
        "date": 1675530143986,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 6831.679517228269,
            "unit": "ns/iter",
            "extra": "iterations: 111357\ncpu: 6819.671866160187 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5773.371026488464,
            "unit": "ns/iter",
            "extra": "iterations: 106801\ncpu: 5772.871040533329 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10633.62642759613,
            "unit": "ns/iter",
            "extra": "iterations: 60066\ncpu: 10632.890487130819 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 8013.622221460207,
            "unit": "ns/iter",
            "extra": "iterations: 87501\ncpu: 8011.164443834926 ns\nthreads: 1"
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
          "id": "5bad7e3f2544bae8b52235e4b687f0213a757cc1",
          "message": "fix: handle ADA_HAS_ICU properly",
          "timestamp": "2023-02-04T13:22:35-05:00",
          "tree_id": "124673c59b4715e8506640ae1f2ad68bccc0514d",
          "url": "https://github.com/ada-url/ada/commit/5bad7e3f2544bae8b52235e4b687f0213a757cc1"
        },
        "date": 1675535056531,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5860.516632988746,
            "unit": "ns/iter",
            "extra": "iterations: 119762\ncpu: 5845.599605885005 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5181.054189270216,
            "unit": "ns/iter",
            "extra": "iterations: 135119\ncpu: 5180.225578934123 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10870.187997702624,
            "unit": "ns/iter",
            "extra": "iterations: 64421\ncpu: 10850.761397680883 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7697.044810304766,
            "unit": "ns/iter",
            "extra": "iterations: 88194\ncpu: 7696.799101979728 ns\nthreads: 1"
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
          "id": "0cfea874630265c8e0a597606e317c6323e834c3",
          "message": "Adding a new file where we can put basic tests. (#203)\n\n* Adding a new file where we can put basic tests.\r\n\r\n* Adding a test for the reverse.\r\n\r\n* More tests.\r\n\r\n* Testing all examples from the README.\r\n\r\n* Minor fix\r\n\r\n* Build everything",
          "timestamp": "2023-02-04T15:08:07-05:00",
          "tree_id": "f1be2b483e46ac69e16d29c15fe319a035a1a803",
          "url": "https://github.com/ada-url/ada/commit/0cfea874630265c8e0a597606e317c6323e834c3"
        },
        "date": 1675541420207,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5855.097347577914,
            "unit": "ns/iter",
            "extra": "iterations: 119438\ncpu: 5853.720758887457 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5219.292581518394,
            "unit": "ns/iter",
            "extra": "iterations: 134448\ncpu: 5218.897268832559 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10897.638527903882,
            "unit": "ns/iter",
            "extra": "iterations: 64561\ncpu: 10897.462864577692 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7531.870669095189,
            "unit": "ns/iter",
            "extra": "iterations: 92244\ncpu: 7531.486058713844 ns\nthreads: 1"
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
          "id": "c01e3868cb78654c38973407c83662dfdc3b08d2",
          "message": "Patching for Windows.",
          "timestamp": "2023-02-04T16:17:27-05:00",
          "tree_id": "edcc46879d4a74ec7a226e3318cc63cda154c062",
          "url": "https://github.com/ada-url/ada/commit/c01e3868cb78654c38973407c83662dfdc3b08d2"
        },
        "date": 1675545535007,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 6242.709058894192,
            "unit": "ns/iter",
            "extra": "iterations: 107905\ncpu: 6241.440155692508 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5713.840121160044,
            "unit": "ns/iter",
            "extra": "iterations: 118521\ncpu: 5711.9742492891555 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10891.592907538858,
            "unit": "ns/iter",
            "extra": "iterations: 59387\ncpu: 10890.383417246201 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7614.659877017801,
            "unit": "ns/iter",
            "extra": "iterations: 101478\ncpu: 7614.152821301169 ns\nthreads: 1"
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
          "id": "ebb34802afe573d3fe97fdcbd2c3be22b6faa60d",
          "message": "fix: logging errors",
          "timestamp": "2023-02-05T22:29:21-05:00",
          "tree_id": "6b8d7c4fd881293811db6635950ef2873f0fb789",
          "url": "https://github.com/ada-url/ada/commit/ebb34802afe573d3fe97fdcbd2c3be22b6faa60d"
        },
        "date": 1675654218443,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5858.894313026432,
            "unit": "ns/iter",
            "extra": "iterations: 119466\ncpu: 5856.354109118913 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5253.391217235151,
            "unit": "ns/iter",
            "extra": "iterations: 133261\ncpu: 5252.6087902687195 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10516.41582092245,
            "unit": "ns/iter",
            "extra": "iterations: 66608\ncpu: 10516.137701177038 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7420.9291443135935,
            "unit": "ns/iter",
            "extra": "iterations: 93387\ncpu: 7420.553181920396 ns\nthreads: 1"
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
          "id": "9e345e88800793d04bdb282fcf53c06d14facd91",
          "message": "build: disable ccache from all workflows",
          "timestamp": "2023-02-06T14:18:02-05:00",
          "tree_id": "f28388c4acf778f3688ef8130bdb4efe59279e5e",
          "url": "https://github.com/ada-url/ada/commit/9e345e88800793d04bdb282fcf53c06d14facd91"
        },
        "date": 1675711172618,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5875.403807564811,
            "unit": "ns/iter",
            "extra": "iterations: 118606\ncpu: 5868.986391919464 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5277.0046322532635,
            "unit": "ns/iter",
            "extra": "iterations: 132333\ncpu: 5274.973740488011 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10514.842318544675,
            "unit": "ns/iter",
            "extra": "iterations: 66628\ncpu: 10514.016629645193 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7659.119459152081,
            "unit": "ns/iter",
            "extra": "iterations: 91412\ncpu: 7659.009758018642 ns\nthreads: 1"
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
          "id": "5ea97db7ee32049bf6bd596b45373552c1f71848",
          "message": "build: remove `mkdir docs` command",
          "timestamp": "2023-02-06T14:30:56-05:00",
          "tree_id": "29302ff4a9d9fc71236b218db994f832231e9dea",
          "url": "https://github.com/ada-url/ada/commit/5ea97db7ee32049bf6bd596b45373552c1f71848"
        },
        "date": 1675711969892,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5942.971755212013,
            "unit": "ns/iter",
            "extra": "iterations: 117473\ncpu: 5941.163501400323 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5262.442247025467,
            "unit": "ns/iter",
            "extra": "iterations: 133136\ncpu: 5257.242218483356 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10573.023083649923,
            "unit": "ns/iter",
            "extra": "iterations: 66324\ncpu: 10571.38743139738 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7480.967587289399,
            "unit": "ns/iter",
            "extra": "iterations: 94284\ncpu: 7480.614950574859 ns\nthreads: 1"
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
          "id": "adc93ac27be6da440a23dc464bd4ad91bd04e29d",
          "message": "test: add more edge cases",
          "timestamp": "2023-02-06T19:44:55-05:00",
          "tree_id": "b77d05323306984aeb2ca5857a96c85be4b701f6",
          "url": "https://github.com/ada-url/ada/commit/adc93ac27be6da440a23dc464bd4ad91bd04e29d"
        },
        "date": 1675730781794,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5812.9752395047535,
            "unit": "ns/iter",
            "extra": "iterations: 121605\ncpu: 5803.068952756877 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5190.436298757515,
            "unit": "ns/iter",
            "extra": "iterations: 134236\ncpu: 5188.728805983491 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10344.088515613512,
            "unit": "ns/iter",
            "extra": "iterations: 67570\ncpu: 10343.168565931624 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7303.183459221343,
            "unit": "ns/iter",
            "extra": "iterations: 96779\ncpu: 7302.2432552516575 ns\nthreads: 1"
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
          "id": "40719fcf5a32402205a1b930ddf181b85be75e3c",
          "message": "fix: potentially strip trailing spaces from opaque path",
          "timestamp": "2023-02-07T13:49:11-05:00",
          "tree_id": "f505c7de26ff8d10e9ebe617790cbb7ab6048b86",
          "url": "https://github.com/ada-url/ada/commit/40719fcf5a32402205a1b930ddf181b85be75e3c"
        },
        "date": 1675795864655,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 6006.148538241339,
            "unit": "ns/iter",
            "extra": "iterations: 117256\ncpu: 5979.219826703964 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5410.632882673608,
            "unit": "ns/iter",
            "extra": "iterations: 129144\ncpu: 5409.954004831815 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10373.593356529636,
            "unit": "ns/iter",
            "extra": "iterations: 67826\ncpu: 10359.229499012179 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7299.424212628919,
            "unit": "ns/iter",
            "extra": "iterations: 96619\ncpu: 7298.9380970616585 ns\nthreads: 1"
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
          "id": "9b3001a6d7225d10c76358bacc33d82911f2a8dc",
          "message": "chore: release v1.0.1",
          "timestamp": "2023-02-07T17:26:54-05:00",
          "tree_id": "2fa2f944add986881078db990b8d92d9adab77f3",
          "url": "https://github.com/ada-url/ada/commit/9b3001a6d7225d10c76358bacc33d82911f2a8dc"
        },
        "date": 1675808899319,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5767.628720415899,
            "unit": "ns/iter",
            "extra": "iterations: 121391\ncpu: 5761.610827820843 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5220.394555487012,
            "unit": "ns/iter",
            "extra": "iterations: 133933\ncpu: 5218.883322258144 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10329.102183315625,
            "unit": "ns/iter",
            "extra": "iterations: 67741\ncpu: 10327.23166177057 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7381.652036527997,
            "unit": "ns/iter",
            "extra": "iterations: 94941\ncpu: 7380.321462803214 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "debadree333@gmail.com",
            "name": "Debadree Chatterjee",
            "username": "debadree25"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "52f15ef4295b940aa2008f7b29b658d53461dd5a",
          "message": "feat: simplify impl of set_host and set_hostname (#215)\n\n* feat: simplify impl of set_host and set_hostname\r\n\r\n* fixup! remove space, move function below setters",
          "timestamp": "2023-02-09T11:29:53-05:00",
          "tree_id": "d99de803e0a1dbc4bff3206eed0d68bb2dfa7bcf",
          "url": "https://github.com/ada-url/ada/commit/52f15ef4295b940aa2008f7b29b658d53461dd5a"
        },
        "date": 1675960282111,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5783.284634653697,
            "unit": "ns/iter",
            "extra": "iterations: 117765\ncpu: 5763.206385598438 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5203.510060145733,
            "unit": "ns/iter",
            "extra": "iterations: 134839\ncpu: 5198.9899064810625 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10371.610666310826,
            "unit": "ns/iter",
            "extra": "iterations: 67446\ncpu: 10370.540877146159 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7303.110678179141,
            "unit": "ns/iter",
            "extra": "iterations: 96243\ncpu: 7302.254709433415 ns\nthreads: 1"
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
          "id": "ae9233e86918b4f9ad42a68f3200d65c7a182888",
          "message": "Optimize the ipv6 serializer (#220)\n\n* Optimizing serialization\r\n\r\n* Saving.\r\n\r\n* Better documentation.",
          "timestamp": "2023-02-13T17:26:54-05:00",
          "tree_id": "a4deee5a18a67d404f1e5ec442e8226597c22067",
          "url": "https://github.com/ada-url/ada/commit/ae9233e86918b4f9ad42a68f3200d65c7a182888"
        },
        "date": 1676327301964,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5372.804912221584,
            "unit": "ns/iter",
            "extra": "iterations: 130613\ncpu: 5355.963801459274 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4722.124057485867,
            "unit": "ns/iter",
            "extra": "iterations: 148141\ncpu: 4721.660445116477 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10455.9349427903,
            "unit": "ns/iter",
            "extra": "iterations: 66772\ncpu: 10455.375007488172 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7545.512245205259,
            "unit": "ns/iter",
            "extra": "iterations: 93016\ncpu: 7545.4029414294355 ns\nthreads: 1"
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
          "id": "f9fdf1c251013dcfa927a90c993a63922bb0694e",
          "message": "build: use correct author format for wpt-updater",
          "timestamp": "2023-02-18T11:26:50-05:00",
          "tree_id": "54f901e6be55507bd8a462f5c623a42477c0ee76",
          "url": "https://github.com/ada-url/ada/commit/f9fdf1c251013dcfa927a90c993a63922bb0694e"
        },
        "date": 1676737767746,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5363.556995928857,
            "unit": "ns/iter",
            "extra": "iterations: 130676\ncpu: 5357.93259665126 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4735.752529998343,
            "unit": "ns/iter",
            "extra": "iterations: 147925\ncpu: 4734.850092952511 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10485.760280331431,
            "unit": "ns/iter",
            "extra": "iterations: 66778\ncpu: 10471.999760400131 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 7529.345995001367,
            "unit": "ns/iter",
            "extra": "iterations: 93221\ncpu: 7529.232683622787 ns\nthreads: 1"
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
          "id": "487c098557bbafa5953d12adbd224e7d7205cffd",
          "message": "Update README.md",
          "timestamp": "2023-02-03T16:36:02-05:00",
          "tree_id": "cca2d4c6a8643401588b68dda927765e9bf3a0cd",
          "url": "https://github.com/ada-url/ada/commit/487c098557bbafa5953d12adbd224e7d7205cffd"
        },
        "date": 1675460217559,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 415036.20619785757,
            "unit": "ns/iter",
            "extra": "iterations: 1678\ncpu: 414838.2598331347 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 438446.53551225044,
            "unit": "ns/iter",
            "extra": "iterations: 1591\ncpu: 438429.16404776875 ns\nthreads: 1"
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
          "id": "a1c32a52c293ff17f329c5e561f2467c51ea69a3",
          "message": "docs: update namespace definitions",
          "timestamp": "2023-02-03T17:01:28-05:00",
          "tree_id": "e74bd9e20da14bee13297bab5ddc56aeb15d90b4",
          "url": "https://github.com/ada-url/ada/commit/a1c32a52c293ff17f329c5e561f2467c51ea69a3"
        },
        "date": 1675461768231,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 457449.59714100044,
            "unit": "ns/iter",
            "extra": "iterations: 1539\ncpu: 457093.0474333983 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 486022.28313672775,
            "unit": "ns/iter",
            "extra": "iterations: 1441\ncpu: 485990.6315058988 ns\nthreads: 1"
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
          "id": "4c76670329ad2bd2b1c7f9541b2faee923086438",
          "message": "build: add singleheader files to gitignore",
          "timestamp": "2023-02-04T12:01:29-05:00",
          "tree_id": "061cb04be2908dcba5a3d204eab85c46628c0e0c",
          "url": "https://github.com/ada-url/ada/commit/4c76670329ad2bd2b1c7f9541b2faee923086438"
        },
        "date": 1675530147654,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 504202.08299999556,
            "unit": "ns/iter",
            "extra": "iterations: 1000\ncpu: 502860.70000000007 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 486975.67414156784,
            "unit": "ns/iter",
            "extra": "iterations: 1427\ncpu: 486951.15627189906 ns\nthreads: 1"
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
          "id": "5bad7e3f2544bae8b52235e4b687f0213a757cc1",
          "message": "fix: handle ADA_HAS_ICU properly",
          "timestamp": "2023-02-04T13:22:35-05:00",
          "tree_id": "124673c59b4715e8506640ae1f2ad68bccc0514d",
          "url": "https://github.com/ada-url/ada/commit/5bad7e3f2544bae8b52235e4b687f0213a757cc1"
        },
        "date": 1675535061786,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 415228.6248520623,
            "unit": "ns/iter",
            "extra": "iterations: 1690\ncpu: 415210.76923076925 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 435915.33873985434,
            "unit": "ns/iter",
            "extra": "iterations: 1603\ncpu: 435897.8165938863 ns\nthreads: 1"
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
          "id": "0cfea874630265c8e0a597606e317c6323e834c3",
          "message": "Adding a new file where we can put basic tests. (#203)\n\n* Adding a new file where we can put basic tests.\r\n\r\n* Adding a test for the reverse.\r\n\r\n* More tests.\r\n\r\n* Testing all examples from the README.\r\n\r\n* Minor fix\r\n\r\n* Build everything",
          "timestamp": "2023-02-04T15:08:07-05:00",
          "tree_id": "f1be2b483e46ac69e16d29c15fe319a035a1a803",
          "url": "https://github.com/ada-url/ada/commit/0cfea874630265c8e0a597606e317c6323e834c3"
        },
        "date": 1675541424596,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 414331.37277051527,
            "unit": "ns/iter",
            "extra": "iterations: 1682\ncpu: 414322.5326991677 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 437712.27781392756,
            "unit": "ns/iter",
            "extra": "iterations: 1537\ncpu: 437687.50813272595 ns\nthreads: 1"
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
          "id": "c01e3868cb78654c38973407c83662dfdc3b08d2",
          "message": "Patching for Windows.",
          "timestamp": "2023-02-04T16:17:27-05:00",
          "tree_id": "edcc46879d4a74ec7a226e3318cc63cda154c062",
          "url": "https://github.com/ada-url/ada/commit/c01e3868cb78654c38973407c83662dfdc3b08d2"
        },
        "date": 1675545539579,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 474844.62620028487,
            "unit": "ns/iter",
            "extra": "iterations: 1458\ncpu: 474436.2139917695 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 505778.2968980782,
            "unit": "ns/iter",
            "extra": "iterations: 1354\ncpu: 505719.4977843426 ns\nthreads: 1"
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
          "id": "ebb34802afe573d3fe97fdcbd2c3be22b6faa60d",
          "message": "fix: logging errors",
          "timestamp": "2023-02-05T22:29:21-05:00",
          "tree_id": "6b8d7c4fd881293811db6635950ef2873f0fb789",
          "url": "https://github.com/ada-url/ada/commit/ebb34802afe573d3fe97fdcbd2c3be22b6faa60d"
        },
        "date": 1675654223167,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 409046.79882699176,
            "unit": "ns/iter",
            "extra": "iterations: 1705\ncpu: 409020.8797653959 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 438674.75203506835,
            "unit": "ns/iter",
            "extra": "iterations: 1597\ncpu: 438645.83594239206 ns\nthreads: 1"
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
          "id": "9e345e88800793d04bdb282fcf53c06d14facd91",
          "message": "build: disable ccache from all workflows",
          "timestamp": "2023-02-06T14:18:02-05:00",
          "tree_id": "f28388c4acf778f3688ef8130bdb4efe59279e5e",
          "url": "https://github.com/ada-url/ada/commit/9e345e88800793d04bdb282fcf53c06d14facd91"
        },
        "date": 1675711177320,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 409661.76321972447,
            "unit": "ns/iter",
            "extra": "iterations: 1702\ncpu: 409611.92714453576 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 442065.70495917974,
            "unit": "ns/iter",
            "extra": "iterations: 1593\ncpu: 442031.88951663545 ns\nthreads: 1"
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
          "id": "5ea97db7ee32049bf6bd596b45373552c1f71848",
          "message": "build: remove `mkdir docs` command",
          "timestamp": "2023-02-06T14:30:56-05:00",
          "tree_id": "29302ff4a9d9fc71236b218db994f832231e9dea",
          "url": "https://github.com/ada-url/ada/commit/5ea97db7ee32049bf6bd596b45373552c1f71848"
        },
        "date": 1675711975149,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 407954.4257075527,
            "unit": "ns/iter",
            "extra": "iterations: 1696\ncpu: 407933.0778301886 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 437920.4449311574,
            "unit": "ns/iter",
            "extra": "iterations: 1598\ncpu: 437900.6883604503 ns\nthreads: 1"
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
          "id": "adc93ac27be6da440a23dc464bd4ad91bd04e29d",
          "message": "test: add more edge cases",
          "timestamp": "2023-02-06T19:44:55-05:00",
          "tree_id": "b77d05323306984aeb2ca5857a96c85be4b701f6",
          "url": "https://github.com/ada-url/ada/commit/adc93ac27be6da440a23dc464bd4ad91bd04e29d"
        },
        "date": 1675730786091,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 456733.21881123236,
            "unit": "ns/iter",
            "extra": "iterations: 1531\ncpu: 456681.31939908554 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 489442.1159217959,
            "unit": "ns/iter",
            "extra": "iterations: 1432\ncpu: 489379.67877094966 ns\nthreads: 1"
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
          "id": "40719fcf5a32402205a1b930ddf181b85be75e3c",
          "message": "fix: potentially strip trailing spaces from opaque path",
          "timestamp": "2023-02-07T13:49:11-05:00",
          "tree_id": "f505c7de26ff8d10e9ebe617790cbb7ab6048b86",
          "url": "https://github.com/ada-url/ada/commit/40719fcf5a32402205a1b930ddf181b85be75e3c"
        },
        "date": 1675795869104,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 460539.2311722415,
            "unit": "ns/iter",
            "extra": "iterations: 1527\ncpu: 459192.14145383105 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 486170.0416666695,
            "unit": "ns/iter",
            "extra": "iterations: 1440\ncpu: 486132.8472222221 ns\nthreads: 1"
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
          "id": "9b3001a6d7225d10c76358bacc33d82911f2a8dc",
          "message": "chore: release v1.0.1",
          "timestamp": "2023-02-07T17:26:54-05:00",
          "tree_id": "2fa2f944add986881078db990b8d92d9adab77f3",
          "url": "https://github.com/ada-url/ada/commit/9b3001a6d7225d10c76358bacc33d82911f2a8dc"
        },
        "date": 1675808903631,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 457606.36191097344,
            "unit": "ns/iter",
            "extra": "iterations: 1528\ncpu: 457144.6989528796 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 487061.7176634122,
            "unit": "ns/iter",
            "extra": "iterations: 1438\ncpu: 486997.21835883154 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "debadree333@gmail.com",
            "name": "Debadree Chatterjee",
            "username": "debadree25"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "52f15ef4295b940aa2008f7b29b658d53461dd5a",
          "message": "feat: simplify impl of set_host and set_hostname (#215)\n\n* feat: simplify impl of set_host and set_hostname\r\n\r\n* fixup! remove space, move function below setters",
          "timestamp": "2023-02-09T11:29:53-05:00",
          "tree_id": "d99de803e0a1dbc4bff3206eed0d68bb2dfa7bcf",
          "url": "https://github.com/ada-url/ada/commit/52f15ef4295b940aa2008f7b29b658d53461dd5a"
        },
        "date": 1675960287310,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 454627.96995427454,
            "unit": "ns/iter",
            "extra": "iterations: 1531\ncpu: 454400.4572175049 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 486051.63541666954,
            "unit": "ns/iter",
            "extra": "iterations: 1440\ncpu: 485995.34722222213 ns\nthreads: 1"
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
          "id": "ae9233e86918b4f9ad42a68f3200d65c7a182888",
          "message": "Optimize the ipv6 serializer (#220)\n\n* Optimizing serialization\r\n\r\n* Saving.\r\n\r\n* Better documentation.",
          "timestamp": "2023-02-13T17:26:54-05:00",
          "tree_id": "a4deee5a18a67d404f1e5ec442e8226597c22067",
          "url": "https://github.com/ada-url/ada/commit/ae9233e86918b4f9ad42a68f3200d65c7a182888"
        },
        "date": 1676327307174,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL",
            "value": 414025.099408293,
            "unit": "ns/iter",
            "extra": "iterations: 1690\ncpu: 414013.49112426036 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 435826.8384279525,
            "unit": "ns/iter",
            "extra": "iterations: 1603\ncpu: 435805.55208983144 ns\nthreads: 1"
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
          "id": "487c098557bbafa5953d12adbd224e7d7205cffd",
          "message": "Update README.md",
          "timestamp": "2023-02-03T16:36:02-05:00",
          "tree_id": "cca2d4c6a8643401588b68dda927765e9bf3a0cd",
          "url": "https://github.com/ada-url/ada/commit/487c098557bbafa5953d12adbd224e7d7205cffd"
        },
        "date": 1675460223119,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5181.956594100584,
            "unit": "ns/iter",
            "extra": "iterations: 134590\ncpu: 5181.68957574857 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4624.643852643289,
            "unit": "ns/iter",
            "extra": "iterations: 151252\ncpu: 4622.164335017058 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10035.9521722316,
            "unit": "ns/iter",
            "extra": "iterations: 69813\ncpu: 10035.79992265051 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5830.069993508584,
            "unit": "ns/iter",
            "extra": "iterations: 120154\ncpu: 5829.665262912596 ns\nthreads: 1"
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
          "id": "a1c32a52c293ff17f329c5e561f2467c51ea69a3",
          "message": "docs: update namespace definitions",
          "timestamp": "2023-02-03T17:01:28-05:00",
          "tree_id": "e74bd9e20da14bee13297bab5ddc56aeb15d90b4",
          "url": "https://github.com/ada-url/ada/commit/a1c32a52c293ff17f329c5e561f2467c51ea69a3"
        },
        "date": 1675461773336,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5293.6700461874825,
            "unit": "ns/iter",
            "extra": "iterations: 132070\ncpu: 5292.887105322936 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4691.713281140157,
            "unit": "ns/iter",
            "extra": "iterations: 149317\ncpu: 4688.086420166493 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 9741.261425704806,
            "unit": "ns/iter",
            "extra": "iterations: 71768\ncpu: 9740.683870248578 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5847.672983479088,
            "unit": "ns/iter",
            "extra": "iterations: 117306\ncpu: 5847.294256048283 ns\nthreads: 1"
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
          "id": "4c76670329ad2bd2b1c7f9541b2faee923086438",
          "message": "build: add singleheader files to gitignore",
          "timestamp": "2023-02-04T12:01:29-05:00",
          "tree_id": "061cb04be2908dcba5a3d204eab85c46628c0e0c",
          "url": "https://github.com/ada-url/ada/commit/4c76670329ad2bd2b1c7f9541b2faee923086438"
        },
        "date": 1675530151799,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5546.11650572573,
            "unit": "ns/iter",
            "extra": "iterations: 111428\ncpu: 5543.947661270058 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5095.055550000041,
            "unit": "ns/iter",
            "extra": "iterations: 100000\ncpu: 5094.718 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10048.785409679262,
            "unit": "ns/iter",
            "extra": "iterations: 65893\ncpu: 10048.607591094653 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 6747.387980307217,
            "unit": "ns/iter",
            "extra": "iterations: 100951\ncpu: 6746.578042812851 ns\nthreads: 1"
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
          "id": "5bad7e3f2544bae8b52235e4b687f0213a757cc1",
          "message": "fix: handle ADA_HAS_ICU properly",
          "timestamp": "2023-02-04T13:22:35-05:00",
          "tree_id": "124673c59b4715e8506640ae1f2ad68bccc0514d",
          "url": "https://github.com/ada-url/ada/commit/5bad7e3f2544bae8b52235e4b687f0213a757cc1"
        },
        "date": 1675535067353,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5205.50907200415,
            "unit": "ns/iter",
            "extra": "iterations: 134645\ncpu: 5202.256303613205 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4652.130430473139,
            "unit": "ns/iter",
            "extra": "iterations: 151345\ncpu: 4626.539363705441 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10165.782192094302,
            "unit": "ns/iter",
            "extra": "iterations: 69924\ncpu: 10159.530347234142 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5787.128035010834,
            "unit": "ns/iter",
            "extra": "iterations: 121334\ncpu: 5786.946775017722 ns\nthreads: 1"
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
          "id": "0cfea874630265c8e0a597606e317c6323e834c3",
          "message": "Adding a new file where we can put basic tests. (#203)\n\n* Adding a new file where we can put basic tests.\r\n\r\n* Adding a test for the reverse.\r\n\r\n* More tests.\r\n\r\n* Testing all examples from the README.\r\n\r\n* Minor fix\r\n\r\n* Build everything",
          "timestamp": "2023-02-04T15:08:07-05:00",
          "tree_id": "f1be2b483e46ac69e16d29c15fe319a035a1a803",
          "url": "https://github.com/ada-url/ada/commit/0cfea874630265c8e0a597606e317c6323e834c3"
        },
        "date": 1675541429813,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5204.666636997513,
            "unit": "ns/iter",
            "extra": "iterations: 134820\ncpu: 5201.367749592048 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4627.0783877547065,
            "unit": "ns/iter",
            "extra": "iterations: 151044\ncpu: 4626.828606233945 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10020.811414746997,
            "unit": "ns/iter",
            "extra": "iterations: 69857\ncpu: 10020.48613596347 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5877.829845062079,
            "unit": "ns/iter",
            "extra": "iterations: 119209\ncpu: 5877.4404617101045 ns\nthreads: 1"
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
          "id": "c01e3868cb78654c38973407c83662dfdc3b08d2",
          "message": "Patching for Windows.",
          "timestamp": "2023-02-04T16:17:27-05:00",
          "tree_id": "edcc46879d4a74ec7a226e3318cc63cda154c062",
          "url": "https://github.com/ada-url/ada/commit/c01e3868cb78654c38973407c83662dfdc3b08d2"
        },
        "date": 1675545545058,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5647.14548140367,
            "unit": "ns/iter",
            "extra": "iterations: 125913\ncpu: 5645.957923328012 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 5033.867686737371,
            "unit": "ns/iter",
            "extra": "iterations: 144173\ncpu: 5033.290560645891 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10155.407067390332,
            "unit": "ns/iter",
            "extra": "iterations: 70040\ncpu: 10152.424328954885 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 6406.60071659696,
            "unit": "ns/iter",
            "extra": "iterations: 109406\ncpu: 6405.185273202565 ns\nthreads: 1"
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
          "id": "ebb34802afe573d3fe97fdcbd2c3be22b6faa60d",
          "message": "fix: logging errors",
          "timestamp": "2023-02-05T22:29:21-05:00",
          "tree_id": "6b8d7c4fd881293811db6635950ef2873f0fb789",
          "url": "https://github.com/ada-url/ada/commit/ebb34802afe573d3fe97fdcbd2c3be22b6faa60d"
        },
        "date": 1675654228432,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5217.37586624642,
            "unit": "ns/iter",
            "extra": "iterations: 132901\ncpu: 5216.5965643599375 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4607.840322750496,
            "unit": "ns/iter",
            "extra": "iterations: 151944\ncpu: 4607.606091718002 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10090.780375987595,
            "unit": "ns/iter",
            "extra": "iterations: 69364\ncpu: 10090.718528343232 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5820.437957356255,
            "unit": "ns/iter",
            "extra": "iterations: 120393\ncpu: 5819.958801591459 ns\nthreads: 1"
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
          "id": "9e345e88800793d04bdb282fcf53c06d14facd91",
          "message": "build: disable ccache from all workflows",
          "timestamp": "2023-02-06T14:18:02-05:00",
          "tree_id": "f28388c4acf778f3688ef8130bdb4efe59279e5e",
          "url": "https://github.com/ada-url/ada/commit/9e345e88800793d04bdb282fcf53c06d14facd91"
        },
        "date": 1675711182767,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5223.517238800831,
            "unit": "ns/iter",
            "extra": "iterations: 133739\ncpu: 5219.044556935523 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4602.845522456729,
            "unit": "ns/iter",
            "extra": "iterations: 151802\ncpu: 4602.559913571627 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10097.160295433257,
            "unit": "ns/iter",
            "extra": "iterations: 69322\ncpu: 10096.174374657394 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5819.954821431205,
            "unit": "ns/iter",
            "extra": "iterations: 120234\ncpu: 5819.679125704875 ns\nthreads: 1"
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
          "id": "5ea97db7ee32049bf6bd596b45373552c1f71848",
          "message": "build: remove `mkdir docs` command",
          "timestamp": "2023-02-06T14:30:56-05:00",
          "tree_id": "29302ff4a9d9fc71236b218db994f832231e9dea",
          "url": "https://github.com/ada-url/ada/commit/5ea97db7ee32049bf6bd596b45373552c1f71848"
        },
        "date": 1675711980726,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5290.563946622144,
            "unit": "ns/iter",
            "extra": "iterations: 124471\ncpu: 5287.536855974484 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4602.0596728509345,
            "unit": "ns/iter",
            "extra": "iterations: 152163\ncpu: 4601.328838153821 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10087.32135855164,
            "unit": "ns/iter",
            "extra": "iterations: 69368\ncpu: 10086.787856071964 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5810.564859020059,
            "unit": "ns/iter",
            "extra": "iterations: 120230\ncpu: 5810.148881310823 ns\nthreads: 1"
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
          "id": "adc93ac27be6da440a23dc464bd4ad91bd04e29d",
          "message": "test: add more edge cases",
          "timestamp": "2023-02-06T19:44:55-05:00",
          "tree_id": "b77d05323306984aeb2ca5857a96c85be4b701f6",
          "url": "https://github.com/ada-url/ada/commit/adc93ac27be6da440a23dc464bd4ad91bd04e29d"
        },
        "date": 1675730791221,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5382.813514716281,
            "unit": "ns/iter",
            "extra": "iterations: 130332\ncpu: 5366.212442071019 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4802.171993629634,
            "unit": "ns/iter",
            "extra": "iterations: 145674\ncpu: 4801.801968779604 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 9889.258322369007,
            "unit": "ns/iter",
            "extra": "iterations: 70683\ncpu: 9888.234794787999 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5848.627932240434,
            "unit": "ns/iter",
            "extra": "iterations: 117828\ncpu: 5848.2491428183475 ns\nthreads: 1"
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
          "id": "40719fcf5a32402205a1b930ddf181b85be75e3c",
          "message": "fix: potentially strip trailing spaces from opaque path",
          "timestamp": "2023-02-07T13:49:11-05:00",
          "tree_id": "f505c7de26ff8d10e9ebe617790cbb7ab6048b86",
          "url": "https://github.com/ada-url/ada/commit/40719fcf5a32402205a1b930ddf181b85be75e3c"
        },
        "date": 1675795874210,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5440.267062616201,
            "unit": "ns/iter",
            "extra": "iterations: 127794\ncpu: 5434.337292830649 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4861.473100380569,
            "unit": "ns/iter",
            "extra": "iterations: 144779\ncpu: 4841.550915533329 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 9846.268301902388,
            "unit": "ns/iter",
            "extra": "iterations: 71427\ncpu: 9845.086591905023 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5922.372998672034,
            "unit": "ns/iter",
            "extra": "iterations: 116735\ncpu: 5922.017389814535 ns\nthreads: 1"
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
          "id": "9b3001a6d7225d10c76358bacc33d82911f2a8dc",
          "message": "chore: release v1.0.1",
          "timestamp": "2023-02-07T17:26:54-05:00",
          "tree_id": "2fa2f944add986881078db990b8d92d9adab77f3",
          "url": "https://github.com/ada-url/ada/commit/9b3001a6d7225d10c76358bacc33d82911f2a8dc"
        },
        "date": 1675808908648,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5366.511593847485,
            "unit": "ns/iter",
            "extra": "iterations: 130414\ncpu: 5366.231386200868 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4782.388948893907,
            "unit": "ns/iter",
            "extra": "iterations: 146284\ncpu: 4782.091001066418 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 9778.492849254451,
            "unit": "ns/iter",
            "extra": "iterations: 71531\ncpu: 9778.125567935576 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5915.161040383932,
            "unit": "ns/iter",
            "extra": "iterations: 116803\ncpu: 5913.660608032326 ns\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "debadree333@gmail.com",
            "name": "Debadree Chatterjee",
            "username": "debadree25"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "52f15ef4295b940aa2008f7b29b658d53461dd5a",
          "message": "feat: simplify impl of set_host and set_hostname (#215)\n\n* feat: simplify impl of set_host and set_hostname\r\n\r\n* fixup! remove space, move function below setters",
          "timestamp": "2023-02-09T11:29:53-05:00",
          "tree_id": "d99de803e0a1dbc4bff3206eed0d68bb2dfa7bcf",
          "url": "https://github.com/ada-url/ada/commit/52f15ef4295b940aa2008f7b29b658d53461dd5a"
        },
        "date": 1675960292747,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5349.054153302086,
            "unit": "ns/iter",
            "extra": "iterations: 131257\ncpu: 5329.947355188676 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4686.057409897732,
            "unit": "ns/iter",
            "extra": "iterations: 148720\ncpu: 4683.486417428726 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 10139.76700140553,
            "unit": "ns/iter",
            "extra": "iterations: 69009\ncpu: 10133.350722369541 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5933.562273474641,
            "unit": "ns/iter",
            "extra": "iterations: 116157\ncpu: 5931.5030519038855 ns\nthreads: 1"
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
          "id": "ae9233e86918b4f9ad42a68f3200d65c7a182888",
          "message": "Optimize the ipv6 serializer (#220)\n\n* Optimizing serialization\r\n\r\n* Saving.\r\n\r\n* Better documentation.",
          "timestamp": "2023-02-13T17:26:54-05:00",
          "tree_id": "a4deee5a18a67d404f1e5ec442e8226597c22067",
          "url": "https://github.com/ada-url/ada/commit/ae9233e86918b4f9ad42a68f3200d65c7a182888"
        },
        "date": 1676327312781,
        "tool": "googlecpp",
        "benches": [
          {
            "name": "BasicBench_AdaURL_With_Copy",
            "value": 5312.30583636915,
            "unit": "ns/iter",
            "extra": "iterations: 131760\ncpu: 5296.741803278689 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_AdaURL_With_Move",
            "value": 4754.086164256887,
            "unit": "ns/iter",
            "extra": "iterations: 147184\ncpu: 4753.921621915426 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_whatwg",
            "value": 9810.507073256249,
            "unit": "ns/iter",
            "extra": "iterations: 71325\ncpu: 9809.920785138453 ns\nthreads: 1"
          },
          {
            "name": "BasicBench_CURL",
            "value": 5835.7771976282165,
            "unit": "ns/iter",
            "extra": "iterations: 120084\ncpu: 5835.710835748311 ns\nthreads: 1"
          }
        ]
      }
    ]
  }
}