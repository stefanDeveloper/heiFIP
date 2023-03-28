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
        filepath: str,
        output_dir: str,
        pbar,
        preprocessing_type: str,
        min_image_dim: int,
        max_image_dim: int,
        min_packets_per_flow: int,
        remove_duplicates: bool,
        width: str,
        append: bool,
        tiled: bool,
    ):
        img = extractor.create_image()
        pbar.update(1)
        if img != None:
            extractor.save_image(img)

    def start_process(
        self,
        file_queue,
        pbar,
        preprocessing_type,
        min_image_dim,
        max_image_dim,
        min_packets_per_flow,
        remove_duplicates,
        *args,
    ):
        while not file_queue.empty():
            filename, output_dir = file_queue.get()
            self.create_image(
                filename,
                output_dir,
                pbar,
                preprocessing_type,
                min_image_dim,
                max_image_dim,
                min_packets_per_flow,
                remove_duplicates,
                *args,
            )
            file_queue.task_done()

    def run(
        self,
        input_dir: str,
        output_dir: str,
        preprocessing_type,
        min_image_dim: int,
        max_image_dim: int,
        min_packets_per_flow: int,
        remove_duplicates: bool,
        **kwargs,
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
                    preprocessing_type,
                    min_image_dim,
                    max_image_dim,
                    min_packets_per_flow,
                    remove_duplicates,
                    kwargs["width"],
                    kwargs["append"],
                    kwargs["tiled"],
                ),
            )

            thread.daemon = True
            thread.start()
        file_queue.join()
        pbar.close()
