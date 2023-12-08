import asyncio
import logging
import sys
from collections.abc import Generator
from collections.abc import Iterable
from io import StringIO
from itertools import chain
from itertools import islice
from pathlib import Path
from typing import NoReturn
from urllib.error import HTTPError

import pandas as pd
from aiohttp import ClientSession
from aiohttp import TCPConnector

logger = logging.getLogger(__name__)


def create_batch(iterable: Generator, size: int = 5) -> Generator[tuple[str, str], None, None]:
    iterator = iter(iterable)
    for _f in iterator:
        yield chain([_f], islice(iterator, size - 1))


def get_all_plugins() -> Generator[tuple[str, str], None, None]:
    all_plugins = pd.DataFrame()

    for plugin_type in ["input", "filter", "output"]:
        url = f"https://www.elastic.co/guide/en/logstash/current/{plugin_type}-plugins.html"
        logger.info(url)

        plugins = pd.read_html(url, flavor="bs4", match="Plugin")[0]
        plugins.columns = plugins.iloc[0]
        plugins = plugins[1:]
        plugins["type"] = plugin_type

        all_plugins = pd.concat(
            [plugins, all_plugins], axis=0
        )

    logger.info(f"Number of plugins: {len(all_plugins)}")
    return all_plugins[["type", "Plugin"]].to_records(index=False)


async def fetch(_session: ClientSession, plugin: tuple[str, str]) -> str:
    plugin_type, plugin_name = plugin
    plugin_string = ""
    url = f"https://www.elastic.co/guide/en/logstash/current/plugins-{plugin_type}s-{plugin_name}.html"
    logger.info(url)

    try:
        async with (_session.get(url) as response):
            if response.status == 200:

                plugin_string = pd.concat(
                    pd.read_html(
                        StringIO(await response.text()),
                        flavor="bs4",
                        match="Setting"
                    ), axis=0
                ).reset_index(drop=True).to_string()

            else:
                logger.warning(f"{url} status code: {response.status}")

    except (ValueError, HTTPError) as e:
        logger.warning(f"{url} - {e}")

    return f"#\n# {plugin_type.upper()} - {plugin_name}\n#\n\n{plugin_string}\n\n"


async def fetch_all(_session: ClientSession, plugins: Iterable):
    return await asyncio.gather(*[
        asyncio.create_task(fetch(_session, p)) for p in plugins
    ])


async def main() -> NoReturn:
    logger.setLevel(logging.DEBUG)
    logger.addHandler(
        logging.StreamHandler(sys.stdout)
    )
    tcp_limit = 10
    plugins = []
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "cs-CZ,cs;q=0.9",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    async with ClientSession(connector=TCPConnector(limit=tcp_limit), headers=headers) as session:
        for batch in create_batch(get_all_plugins(), tcp_limit):
            plugins += await fetch_all(session, batch)

    Path("/tmp/elastic_plugins.txt").write_text("\n".join(plugins))


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
