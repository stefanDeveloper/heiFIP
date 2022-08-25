import glob
import os
from queue import Queue
from threading import Thread
from PIL import Image as PILImage
from fip.image import FlowImage

from fip.packets import PacketProcessor
from tqdm import tqdm


class Runner():

    def __init__(self, thread_number) -> None:
        self.thread_number = thread_number

    def create_image(self, filename, output_dir, pbar, width: str, append: bool, tiled: bool):
        with PacketProcessor(dir=filename) as result:
            for pkt in result:
                image = FlowImage(pkt.packets, width=width,
                                  append=append, tiled=tiled)
                im = PILImage.fromarray(image["matrix"])
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                im.save(f'{output_dir}/{pkt.file}_processed.png')
                pbar.update(1)

    def start_process(self, file_queue, pbar, *args):
        while not file_queue.empty():
            filename, output_dir = file_queue.get()
            self.create_image(filename, output_dir, pbar, *args)
            file_queue.task_done()

    def run(self, input_dir, output_dir, **kwargs):
        # Get all executable files in input directory and add them into queue
        file_queue = Queue()
        folders = [f for f in glob.glob(input_dir + "**/", recursive=True)]
        files = [f for f in glob.glob(input_dir + "**/*.pcap", recursive=True)]
        for folder in folders:
            sub_dir = folder.replace(input_dir, "")
            file_queue.put((folder, f'{output_dir}/{sub_dir}'))

        # Start thread
        pbar = tqdm(total=len(files))
        for _ in range(self.thread_number):
            thread = Thread(target=self.start_process, args=(
                file_queue, pbar, kwargs['width'],  kwargs['append'], kwargs['tiled']))
            thread.daemon = True
            thread.start()

        file_queue.join()
        pbar.close()
