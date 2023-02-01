window.BENCHMARK_DATA = {
  "lastUpdate": 1675287808628,
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
      }
    ]
  }
}