async def create_and_fetch_identity(user, user_address, headers=None):
    UDP_BASE_URL = os.getenv("UDP_BASE_URL")
    create_identity_url = f"{UDP_BASE_URL}/identity/create"
    fetch_identity_url = f"{UDP_BASE_URL}/identity/get"

    data = {"walletAddress": user_address}

    try:
        # Single timeout session for all operations
        timeout = aiohttp.ClientTimeout(total=60)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # First try the simplest thing - direct fetch to see if identity already exists
            print(
                f"[DEBUG] First checking if identity already exists for {user_address}"
            )
            try:
                async with session.post(
                    fetch_identity_url, json=data
                ) as initial_fetch_response:
                    initial_fetch_response.raise_for_status()
                    initial_fetch_data = await initial_fetch_response.json()

                    if (
                        initial_fetch_data.get("data")
                        and initial_fetch_data["data"] != "0"
                    ):
                        omnikey_id = initial_fetch_data["data"]
                        print(f"[DEBUG] Got existing identity directly: {omnikey_id}")
                        return omnikey_id
                    else:
                        print(
                            f"[DEBUG] Initial fetch returned: {initial_fetch_data.get('data', 'None')}"
                        )
            except Exception as e:
                print(f"[DEBUG] Initial fetch check failed: {str(e)}")

            # If we get here, we need to create a new identity
            print(f"[DEBUG] No existing identity found, creating new one")

            # Create identity
            create_start = time.time()
            async with session.post(create_identity_url, json=data) as create_response:
                status_code = create_response.status
                create_response.raise_for_status()
                response_json = await create_response.json()
                print(
                    f"[DEBUG] Create identity status: {status_code}, response: {response_json}"
                )

            # Wait a fixed time before first fetch attempt
            await asyncio.sleep(10)

            # Implement retries just for the fetch operation
            max_retries = 3
            retry_delays = [5, 10, 15]  # Simple increasing delays

            for attempt in range(max_retries):
                try:
                    async with session.post(
                        fetch_identity_url, json=data
                    ) as fetch_response:
                        fetch_status = fetch_response.status
                        fetch_response.raise_for_status()
                        fetch_data = await fetch_response.json()

                        if fetch_data.get("data") and fetch_data["data"] != "0":
                            omnikey_id = fetch_data["data"]
                            print(
                                f"[DEBUG] Got valid omnikey_id: {omnikey_id} on attempt {attempt+1}"
                            )
                            return omnikey_id
                        else:
                            print(
                                f"[DEBUG] Invalid omnikey_id: {fetch_data.get('data', 'None')} on attempt {attempt+1}"
                            )

                except Exception as fetch_err:
                    print(f"[ERROR] Fetch attempt {attempt+1} failed: {str(fetch_err)}")

                # Don't wait after the last attempt
                if attempt < max_retries - 1:
                    wait_time = retry_delays[attempt]
                    print(f"[DEBUG] Waiting {wait_time}s before retry {attempt+2}...")
                    await asyncio.sleep(wait_time)

            # If we get here, all retries failed
            print("[ERROR] All fetch attempts failed to return a valid omnikey_id")
            return None

    except Exception as err:
        print(f"[ERROR] Error in create_and_fetch_identity: {str(err)}")
        return None
