/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sshd.common.util;

import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.sshd.common.Closeable;
import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.DefaultSshFuture;
import org.apache.sshd.common.future.SshFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class to help with {@link Closeable}s.
 *
 * @author <a href="mailto:dev@mina.apache.org">Apache MINA SSHD Project</a>
 */
public class CloseableUtils {

    public static CloseFuture closed() {
        CloseFuture future = new DefaultCloseFuture(null);
        future.setClosed();
        return future;
    }

    public static Closeable parallel(final Collection<? extends Closeable> closeables) {
        return parallel(null, closeables);
    }

    public static Closeable parallel(final Object lock, final Collection<? extends Closeable> closeables) {
        return parallel(lock, closeables.toArray(new Closeable[closeables.size()]));
    }

    public static Closeable parallel(final Closeable... closeables) {
        return parallel(null, closeables);
    }

    public static Closeable parallel(final Object lock, final Closeable... closeables) {
        if (closeables.length == 0) {
            return new Closeable() {
                public CloseFuture close(boolean immediately) {
                    final CloseFuture future = new DefaultCloseFuture(lock);
                    future.setClosed();
                    return future;
                }
            };
        } else if (closeables.length == 1) {
            return closeables[0];
        } else {
            return new Closeable() {
                public CloseFuture close(boolean immediately) {
                    final CloseFuture future = new DefaultCloseFuture(lock);
                    final AtomicInteger count = new AtomicInteger(closeables.length);
                    SshFutureListener<CloseFuture> listener = new SshFutureListener<CloseFuture>() {
                        public void operationComplete(CloseFuture f) {
                            if (count.decrementAndGet() == 0) {
                                future.setClosed();
                            }
                        }
                    };
                    for (Closeable c : closeables) {
                        c.close(immediately).addListener(listener);
                    }
                    return future;
                }
            };
        }
    }

    public static Closeable sequential(final Collection<? extends Closeable> closeables) {
        return sequential(null, closeables);
    }

    public static Closeable sequential(final Object lock, final Collection<? extends Closeable> closeables) {
        return sequential(lock, closeables.toArray(new Closeable[closeables.size()]));
    }

    public static Closeable sequential(final Closeable... closeables) {
        return sequential(null, closeables);
    }

    public static Closeable sequential(final Object lock, final Closeable... closeables) {
        if (closeables.length == 0) {
            return new Closeable() {
                public CloseFuture close(boolean immediately) {
                    final CloseFuture future = new DefaultCloseFuture(lock);
                    future.setClosed();
                    return future;
                }
            };
        } else if (closeables.length == 1) {
            return closeables[0];
        } else {
            return new Closeable() {
                public CloseFuture close(final boolean immediately) {
                    final DefaultCloseFuture future = new DefaultCloseFuture(lock);
                    final Iterator<Closeable> iterator = Arrays.asList(closeables).iterator();
                    SshFutureListener<CloseFuture> listener = new SshFutureListener<CloseFuture>() {
                        public void operationComplete(CloseFuture previousFuture) {
                            if (iterator.hasNext()) {
                                Closeable c = iterator.next();
                                CloseFuture nextFuture = c.close(immediately);
                                nextFuture.addListener(this);
                            } else {
                                future.setClosed();
                            }
                        }
                    };
                    listener.operationComplete(null);
                    return future;
                }
            };
        }
    }

    public static SshFuture parallel(final SshFuture... futures) {
        if (futures.length == 0) {
            final DefaultSshFuture<SshFuture> future = new DefaultSshFuture<SshFuture>(null);
            future.setValue(true);
            return future;
        } else if (futures.length == 1) {
            return futures[0];
        } else {
            final CloseFuture future = new DefaultCloseFuture(null);
            final AtomicInteger count = new AtomicInteger(futures.length);
            SshFutureListener<?> listener = new SshFutureListener<SshFuture>() {
                public void operationComplete(SshFuture f) {
                    if (count.decrementAndGet() == 0) {
                        future.setClosed();
                    }
                }
            };
            for (SshFuture f : futures) {
                f.addListener(listener);
            }
            return future;
        }
    }

    public static abstract class AbstractCloseable implements Closeable {

        protected static final int OPENED = 0;
        protected static final int GRACEFUL = 1;
        protected static final int IMMEDIATE = 2;
        protected static final int CLOSED = 3;

        /** Our logger */
        protected final Logger log = LoggerFactory.getLogger(getClass());
        /** Lock object for this session state */
        protected final Object lock = new Object();
        /** State of this object */
        protected final AtomicInteger state = new AtomicInteger();
        /** A future that will be set 'closed' when the object is actually closed */
        protected final CloseFuture closeFuture = new DefaultCloseFuture(lock);

        public CloseFuture close(boolean immediately) {
            if (immediately) {
                if (state.compareAndSet(0, IMMEDIATE) || state.compareAndSet(GRACEFUL, IMMEDIATE)) {
                    log.debug("Closing {} immediately", this);
                    doCloseImmediately();
                } else {
                    log.debug("{} is already {}", this, state.get() == CLOSED ? "closed" : "closing");
                }
            } else {
                if (state.compareAndSet(0, GRACEFUL)) {
                    log.debug("Closing {} gracefully", this);
                    SshFuture grace = doCloseGracefully();
                    if (grace != null) {
                        grace.addListener(new SshFutureListener() {
                            public void operationComplete(SshFuture future) {
                                if (state.compareAndSet(GRACEFUL, IMMEDIATE)) {
                                    doCloseImmediately();
                                }
                            }
                        });
                    } else {
                        if (state.compareAndSet(GRACEFUL, IMMEDIATE)) {
                            doCloseImmediately();
                        }
                    }
                } else {
                    log.debug("{} is already {}", this, state.get() == CLOSED ? "closed" : "closing");
                }
            }
            return closeFuture;
        }

        protected SshFuture doCloseGracefully() {
            return null;
        }

        protected void doCloseImmediately() {
            postClose();
        }

        protected void postClose() {
            closeFuture.setClosed();
            state.set(CLOSED);
            log.debug("{} closed", this);
        }
    }

    public static abstract class AbstractInnerCloseable extends AbstractCloseable {

        protected abstract Closeable getInnerCloseable();

        @Override
        protected SshFuture doCloseGracefully() {
            return getInnerCloseable().close(false);
        }

        @Override
        protected void doCloseImmediately() {
            getInnerCloseable().close(true).addListener(new SshFutureListener<CloseFuture>() {
                public void operationComplete(CloseFuture future) {
                    postClose();
                }
            });
        }
    }

    private CloseableUtils() {
    }
}
