# heiFIP (Flow Image Processor)

Flow Image Processor extracts essential parts of packets from all layers (IPv4, IPv6, TCP, UDP, HTTP, DNS) and converts it into images:

![SMB Connection](./examples/SMB.png?raw=true "SMB Vonnection")


## Getting Started

```sh
# Show help information
>fip -h
Starting FlowImageProcessor CLI
Usage: fip extract [OPTIONS]

Options:
  -rd, --remove_duplicates      Within a single output folder belonging to a
                                single input folder no duplicate images will
                                be produced if two inputs lead to the same
                                image
  -mp, --min_packets INTEGER    Minimum packets that a FlowImage needs to
                                have, 0=No minimum packets per flow
  -maxid, --max_im_dim INTEGER  Maximum dim ouput images can have, 0=No
                                maximum dim
  -mid, --min_im_dim INTEGER    Minimum dim ouput images need to have, 0=No
                                minimum dim
  -p, --preprocess TEXT         Applies a preprocessing to the input data:
                                none: No preprocessing payload: Only payload
                                data is used header: Preprocesses headers
                                (DNS,HTTP,IP,IPv6,TCP,UDP supported) to remove
                                some biasing data
  -t, --threads INTEGER         Number of parallel threads that can be used
  -r, --read PATH
  -w, --write PATH              Destination file path, stores result
                                [required]
  -h, --help                    Show this message and exit.

> fip extract -r /PATH/PCAPs -w /PATH/IMAGES
```

## Citation