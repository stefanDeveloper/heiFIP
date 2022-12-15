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

    def create_image(self, filename, output_dir, pbar, preprocessing_type: str, min_image_dim: int, max_image_dim: int, min_packets_per_flow: int, remove_duplicates: bool, width: str, append: bool, tiled: bool):
        if remove_duplicates:
            images_created = []
        if preprocessing_type not in ["payload", "header"]:
            preprocessing_type = "none"
        with PacketProcessor(dir=filename, preprocessing_type=preprocessing_type) as result:
            for pkt in result:
                # when no file matches the preprocessing
                if len(pkt.packets) == 0 or len(pkt.packets) < min_packets_per_flow:
                    pbar.update(1)
                    continue
                image = FlowImage(pkt.packets, width=width,
                                  append=append, tiled=tiled,
                                  auto_dim=True)
                flow_image = image["matrix"]
                
                if flow_image.shape[0] < min_image_dim or flow_image.shape[1] < min_image_dim:
                    pbar.update(1)
                    continue
                elif max_image_dim != 0 and (max_image_dim < flow_image.shape[0] or max_image_dim < flow_image.shape[1]):
                    pbar.update(1)
                    continue
                if remove_duplicates:
                    im_str = flow_image.tobytes()
                    if im_str in images_created:
                        pbar.update(1)
                        continue

                images_created.append(im_str)
                im = PILImage.fromarray(image["matrix"])
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                im.save(f'{output_dir}/{pkt.file}_processed.png')
                pbar.update(1)

    def start_process(self, file_queue, pbar, preprocessing_type, min_image_dim, max_image_dim, min_packets_per_flow, remove_duplicates, *args):
        while not file_queue.empty():
            filename, output_dir = file_queue.get()
            self.create_image(filename, output_dir, pbar, preprocessing_type, min_image_dim, max_image_dim, min_packets_per_flow, remove_duplicates, *args)
            file_queue.task_done()

    def run(self, input_dir, output_dir, preprocessing_type, min_image_dim, max_image_dim, min_packets_per_flow, remove_duplicates, **kwargs):
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
                file_queue, pbar, preprocessing_type, min_image_dim, max_image_dim, min_packets_per_flow, remove_duplicates, kwargs['width'],  kwargs['append'], kwargs['tiled']))
            thread.daemon = True
            thread.start()

        file_queue.join()
        pbar.close()
