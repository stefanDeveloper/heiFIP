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

    def create_image(self, filename, output_dir, width: str, append: bool, tiled: bool):
        with PacketProcessor(dir=filename) as result:
            for pkt in result:
                image = FlowImage(pkt.packets, width=width,
                                  append=append, tiled=tiled)
                im = PILImage.fromarray(image["matrix"])
                im.save(f'{output_dir}/{pkt.file}_processed.png')

    def start_process(self, file_queue, pbar, *args):
        while not file_queue.empty():
            filename, output_dir = file_queue.get()
            self.create_image(filename, output_dir, *args)
            pbar.update(1)
            file_queue.task_done()

    def run(self, input_dir, output_dir, **kwargs):
        # Get all executable files in input directory and add them into queue
        file_queue = Queue()
        for root, _, files in os.walk(input_dir):
            for filename in files:
                file_path = os.path.join(root, filename)
                file_queue.put((file_path, output_dir))

        # Start thread
        pbar = tqdm(total=file_queue.qsize())
        for _ in range(self.thread_number):
            thread = Thread(target=self.start_process, args=(
                file_queue, pbar, kwargs['width'],  kwargs['append'], kwargs['tiled']))
            thread.daemon = True
            thread.start()

        file_queue.join()
        pbar.close()
