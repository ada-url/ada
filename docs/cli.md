## Command line interface (CLI)

The adaparse command tool takes URL strings (ASCII/UTF-8) and it validates, normalizes and queries them efficiently.

### Command line options

- Options:
    - `-d`, `--diagram`: Print a diagram of the result
    - `-u`, `--url`: URL Parameter (required)
    - `-h`, `--help`: Print usage
    - `-g`, `--get`: Get a specific part of the URL (e.g., 'origin', 'host', etc. as mentioned in the examples above)
    - `-b`, `--benchmark`: Run benchmark for piped file functions
    - `-p`, `--path`: Process all the URLs in a given file
    - `-o`, `--output`: Output the results of the parsing to a file

### Performance

Our `adaparse` tool may outperform other popular alternatives. We offer a [collection of
sets of URLs](https://github.com/ada-url/url-various-datasets) for benchmarking purposes.
The following results are on a MacBook Air 2022 (M2 processor) using LLVM 14. We
compare against [trurl](https://github.com/curl/trurl) version 0.6 (libcurl/7.87.0).

<details>
<summary>With the wikipedia_100k dataset, we get that adaparse can generate normalized URLs about **three times faster than trurl**.</summary>
```
time cat url-various-datasets/wikipedia/wikipedia_100k.txt| trurl --url-file - &> /dev/null   1
cat url-various-datasets/wikipedia/wikipedia_100k.txt  0,00s user 0,01s system 3% cpu 0,179 total
trurl --url-file - &> /dev/null  0,14s user 0,03s system 98% cpu 0,180 total


time cat url-various-datasets/wikipedia/wikipedia_100k.txt| ./build/tools/cli/adaparse -g href &> /dev/null
cat url-various-datasets/wikipedia/wikipedia_100k.txt  0,00s user 0,00s system 10% cpu 0,056 total
./build/tools/cli/adaparse -g href &> /dev/null  0,05s user 0,00s system 93% cpu 0,055 total
```
</details>

<details>
<summary>With the top100 dataset, the adaparse tool is **twice as fast as the trurl**.</summary>
```
time cat url-various-datasets/top100/top100.txt| trurl --url-file - &> /dev/null              1
cat url-various-datasets/top100/top100.txt  0,00s user 0,00s system 4% cpu 0,115 total
trurl --url-file - &> /dev/null  0,09s user 0,02s system 97% cpu 0,113 total

time cat url-various-datasets/top100/top100.txt| ./build/tools/cli/adaparse -g href &> /dev/null
cat url-various-datasets/top100/top100.txt  0,00s user 0,01s system 11% cpu 0,062 total
./build/tools/cli/adaparse -g href &> /dev/null  0,05s user 0,00s system 94% cpu 0,061 total
```
</details>


#### Comparison

```
wikipedia 100k
ada ▏   55 ms ███████▋
trurl ▏  180 ms █████████████████████████

top100
ada ▏   61 ms █████████████▍
trurl ▏  113 ms █████████████████████████
```

The results will vary depending on your system. We invite you to run your own benchmarks.

### Usage/Examples

#### Well-formatted URL

```bash 
adaparse "http://www.google.com"
```
Output: 

```
http://www.google.com
```

#### Diagram

```bash
adaparse -d http://www.google.com/bal\?a\=\=11\#fddfds
```

Output:

```
 http://www.google.com/bal?a==11#fddfds [38 bytes]
      | |             |   |     |
      | |             |   |     `------ hash_start
      | |             |   `------------ search_start 25
      | |             `---------------- pathname_start 21
      | |             `---------------- host_end 21
      | `------------------------------ host_start 7
      | `------------------------------ username_end 7
      `-------------------------------- protocol_end 5
```

#### Pipe Operator

Ada can process URLs from piped input, making it easy to integrate with other command-line tools
that produce ASCII or UTF-8 outputs. Here's an example of how to pipe the output of another command into Ada.
Given a list of URLs, one by line, we may query the normalized URL string (`href`) and detect any malformed URL:

```bash
cat dragonball_url.txt | adaparse --get href
```

Output:
```
http://www.goku.com
http://www.vegeta.com
http://www.gohan.com

```

Our tool supports the passing of arguments to each URL in said file so
that you can query for the hash, the host, the protocol, the port, 
the origin, the search, the password, the username, the pathname
or the hostname:

```bash
cat dragonball_url.txt  | adaparse -g host
```

Output:
```
www.goku.com
www.vegeta.com
www.gohan.com
```

If you omit `-g`, it will only provide a list of invalid URLs. This might be
useful if you want to valid quickly a list of URLs.

### Benchmark Runner

The benchmark flag can be used to output the time it takes to process piped input:

```bash
cat wikipedia_100k.txt | adaparse -b
```

Output:
```
Invalid URL: 1968:_Die_Kinder_der_Diktatur
Invalid URL: 58957:_The_Bluegrass_Guitar_Collection
Invalid URL: 650luc:_Gangsta_Grillz
Invalid URL: Q4%3A57
Invalid URL: Q10%3A47
Invalid URL: Q5%3A45
Invalid URL: Q40%3A28
Invalid URL: 1:1_scale
Invalid URL: 1893:_A_World's_Fair_Mystery
Invalid URL: 12:51_(Krissy_%26_Ericka_song)
Invalid URL: 111:_A_Nelson_Number
Invalid URL: 7:00AM-8%3A00AM_(24_season_5)
Invalid URL: Q53%3A31
read 5209265 bytes in 32819917 ns using 100000 lines, used 160 loads
0.1587226744053009 GB/s
```

#### Saving result to file system

There is an option to output to a file on disk:

```bash 
cat wikipedia_100k.txt | adaparse -o wiki_output.txt
```

As well as read in from a file on disk without going through cat:

```bash
adaparse -p wikipedia_top_100_txt
```

#### Advanced Usage

You may also combine different flags together. E.g. Say one wishes to extract only the host from URLs stored in wikipedia.txt and output it to the test_write.txt file:

```bash
adaparse" -p wikipedia_top100.txt -o test_write.txt -g host -b
```

Output:
```bash
read 5209265 bytes in 26737131 ns using 100000 lines, total_bytes is 5209265 used 160 loads
0.19483260937757307 GB/s(base)
```

Content of test_write.txt:
```bash
(---snip---)
en.wikipedia.org
en.wikipedia.org
en.wikipedia.org
en.wikipedia.org
en.wikipedia.org
en.wikipedia.org
en.wikipedia.org
en.wikipedia.org
en.wikipedia.org
en.wikipedia.org
(---snip---)
```
