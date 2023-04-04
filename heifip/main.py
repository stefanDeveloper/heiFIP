import asyncio
import fnmatch
import glob
import logging
import os
from os.path import dirname, realpath
from queue import Queue
from threading import Thread

from PIL import Image as PILImage
from tqdm import tqdm

from heifip.extractor import FIPExtractor
from heifip.images.flow import FlowImage


class Runner:
    def __init__(self, thread_number) -> None:
        self.thread_number = thread_number
        self.extractor = FIPExtractor()

    def create_image(
        self,
        input_file: str,
        output_dir: str,
        pbar,
        *args
    ):
        imgs = self.extractor.create_image_from_file(input_file, *args)
        pbar.update(1)
        for img in imgs:
            self.extractor.save_image(img, output_dir)

    def start_process(
        self,
        file_queue,
        pbar,
        *args,
    ):
        while not file_queue.empty():
            input_file, output_dir = file_queue.get()
            self.create_image(
                input_file,
                output_dir,
                pbar,
                *args,
            )
            file_queue.task_done()

    def run(
        self,
        input_dir: str,
        output_dir: str,
        *args
    ):

        # Get all executable files in input directory and add them into queue
        file_queue = Queue()
        total_files = 0
        for root, dirnames, filenames in os.walk(input_dir):
            for filename in fnmatch.filter(filenames, "*.pcap"):
                match = os.path.join(root, filename)
                sub_dir = match.replace(input_dir, "")
                file_queue.put((match, f"{output_dir}/{sub_dir}"))
                total_files += 1

        # Start thread
        pbar = tqdm(total=total_files)
        for _ in range(self.thread_number):
            thread = Thread(
                target=self.start_process,
                args=(
                    file_queue,
                    pbar,
                    *args
                ),
            )
            thread.daemon = True
            thread.start()
        file_queue.join()
        pbar.close()
