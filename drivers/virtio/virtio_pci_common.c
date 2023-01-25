/*
 * Virtio PCI driver - common functionality for all device versions
 *
 * This module allows virtio devices to be used over a virtual PCI device.
 * This can be used with QEMU based VMMs like KVM or Xen.
 *
 * Copyright IBM Corp. 2007
 * Copyright Red Hat, Inc. 2014
 *
 * Authors:
 *  Anthony Liguori  <aliguori@us.ibm.com>
 *  Rusty Russell <rusty@rustcorp.com.au>
 *  Michael S. Tsirkin <mst@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#define DEBUG
#include "virtio_pci_common.h"

#ifdef CONFIG_POPCORN_HYPE
#include <popcorn/hype_kvm.h>
#include <popcorn/debug.h>
#endif

static bool force_legacy = false;

#if IS_ENABLED(CONFIG_VIRTIO_PCI_LEGACY)
module_param(force_legacy, bool, 0444);
MODULE_PARM_DESC(force_legacy,
		 "Force legacy mode for transitional virtio 1 devices");
#endif

/* wait for pending irq handlers */
void vp_synchronize_vectors(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	int i;

	if (vp_dev->intx_enabled)
		synchronize_irq(vp_dev->pci_dev->irq);

	for (i = 0; i < vp_dev->msix_vectors; ++i)
		synchronize_irq(vp_dev->msix_entries[i].vector);
}

/* the notify function used when creating a virt queue */
bool vp_notify(struct virtqueue *vq)
{
	/* we write the queue's selector into the notification register to
	 * signal the other end */
#ifdef CONFIG_POPCORN_HYPE
	static u64 cnt = 0;
	cnt++;
	/* guest vm */
	CRITICALNETPK("pophype: net: <%d> %s: %s(): [[[triger vhost im guest]]] "
				"vq %p in_atomic %d #%llu\n",
				smp_processor_id(), __FILE__, __func__, vq, in_atomic(), cnt);
	if (my_nid > 0 || cnt < 20) {
		//POP_PK("pophype: net: #%llu\n", cnt);
		//dump_stack();
	}
	//pophype_set_cpu0();
	/* vq->priv is set as VIRTIO_PCI_QUEUE_NOTIFY when init */
#endif

#ifdef CONFIG_POPCORN_HYPE
	if (vq->devtype == VIRTIO_DEVTYPE_BLK)
		VIRTIOBLKPK("vp_notify: calling iowrite: qid=%d, comm=%s, smp=%d\n", vq->index, current->comm, raw_smp_processor_id());
#endif
	iowrite16(vq->index, (void __iomem *)vq->priv);

#ifdef CONFIG_POPCORN_HYPE
	if (vq->devtype == VIRTIO_DEVTYPE_BLK)
		VIRTIOBLKPK("vp_notify: returned: qid=%d, comm=%s, smp=%d\n", vq->index, current->comm, raw_smp_processor_id());
#endif
	//VIRTIOPKIRQ("vp_notify: we have just trigerred vq=%d\n", vq->index);
	return true;
}

/* Handle a configuration change: Tell driver if it wants to know. */
static irqreturn_t vp_config_changed(int irq, void *opaque)
{
	struct virtio_pci_device *vp_dev = opaque;

#ifdef CONFIG_POPCORN_HYPE
    VPCINETPRINTK("\tpophype: virtio: pci: net: %s():\n", __func__);
#endif
	virtio_config_changed(&vp_dev->vdev);
	return IRQ_HANDLED;
}

/* Notify all virtqueues on an interrupt. */
static irqreturn_t vp_vring_interrupt(int irq, void *opaque)
{
	struct virtio_pci_device *vp_dev = opaque;
	struct virtio_pci_vq_info *info;
	irqreturn_t ret = IRQ_NONE;
	unsigned long flags;

#ifdef CONFIG_POPCORN_HYPE
    VPCINETPRINTK("\tpophype: virtio: pci: net: %s():\n", __func__);
#endif
	spin_lock_irqsave(&vp_dev->lock, flags);
	list_for_each_entry(info, &vp_dev->virtqueues, node) {
		if (vring_interrupt(irq, info->vq) == IRQ_HANDLED)
			ret = IRQ_HANDLED;
	}
	spin_unlock_irqrestore(&vp_dev->lock, flags);

	return ret;
}

/* A small wrapper to also acknowledge the interrupt when it's handled.
 * I really need an EIO hook for the vring so I can ack the interrupt once we
 * know that we'll be handling the IRQ but before we invoke the callback since
 * the callback may notify the host which results in the host attempting to
 * raise an interrupt that we would then mask once we acknowledged the
 * interrupt. */
static irqreturn_t vp_interrupt(int irq, void *opaque)
{
	struct virtio_pci_device *vp_dev = opaque;
	u8 isr;

#ifdef CONFIG_POPCORN_HYPE
    VPCINETPRINTK("\tpophype: virtio: pci: net: %s():\n", __func__);
#endif
	/* reading the ISR has the effect of also clearing it so it's very
	 * important to save off the value. */
	isr = ioread8(vp_dev->isr);

	/* It's definitely not us if the ISR was not high */
	if (!isr)
		return IRQ_NONE;

	/* Configuration change?  Tell driver if it wants to know. */
	if (isr & VIRTIO_PCI_ISR_CONFIG)
		vp_config_changed(irq, opaque);

	return vp_vring_interrupt(irq, opaque);
}

static void vp_free_vectors(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	int i;

	if (vp_dev->intx_enabled) {
		free_irq(vp_dev->pci_dev->irq, vp_dev);
		vp_dev->intx_enabled = 0;
	}

	for (i = 0; i < vp_dev->msix_used_vectors; ++i)
		free_irq(vp_dev->msix_entries[i].vector, vp_dev);

	for (i = 0; i < vp_dev->msix_vectors; i++)
		if (vp_dev->msix_affinity_masks[i])
			free_cpumask_var(vp_dev->msix_affinity_masks[i]);

	if (vp_dev->msix_enabled) {
		/* Disable the vector used for configuration */
		vp_dev->config_vector(vp_dev, VIRTIO_MSI_NO_VECTOR);

		pci_disable_msix(vp_dev->pci_dev);
		vp_dev->msix_enabled = 0;
	}

	vp_dev->msix_vectors = 0;
	vp_dev->msix_used_vectors = 0;
	kfree(vp_dev->msix_names);
	vp_dev->msix_names = NULL;
	kfree(vp_dev->msix_entries);
	vp_dev->msix_entries = NULL;
	kfree(vp_dev->msix_affinity_masks);
	vp_dev->msix_affinity_masks = NULL;
}

static int vp_request_msix_vectors(struct virtio_device *vdev, int nvectors,
				   bool per_vq_vectors)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	const char *name = dev_name(&vp_dev->vdev.dev);
	unsigned i, v;
	int err = -ENOMEM;

#ifdef CONFIG_POPCORN_HYPE
    VPCINETPRINTK("\tpophype: virtio: pci: net: %s():\n", __func__);
#endif

	vp_dev->msix_vectors = nvectors;

	vp_dev->msix_entries = kmalloc(nvectors * sizeof *vp_dev->msix_entries,
				       GFP_KERNEL);
	if (!vp_dev->msix_entries)
		goto error;
	vp_dev->msix_names = kmalloc(nvectors * sizeof *vp_dev->msix_names,
				     GFP_KERNEL);
	if (!vp_dev->msix_names)
		goto error;
	vp_dev->msix_affinity_masks
		= kzalloc(nvectors * sizeof *vp_dev->msix_affinity_masks,
			  GFP_KERNEL);
	if (!vp_dev->msix_affinity_masks)
		goto error;
	for (i = 0; i < nvectors; ++i)
		if (!alloc_cpumask_var(&vp_dev->msix_affinity_masks[i],
					GFP_KERNEL))
			goto error;

	for (i = 0; i < nvectors; ++i)
		vp_dev->msix_entries[i].entry = i;

	err = pci_enable_msix_exact(vp_dev->pci_dev,
				    vp_dev->msix_entries, nvectors);
	if (err)
		goto error;
	vp_dev->msix_enabled = 1;

	/* Set the vector used for configuration */
	v = vp_dev->msix_used_vectors;
	snprintf(vp_dev->msix_names[v], sizeof *vp_dev->msix_names,
		 "%s-config", name);
#ifdef CONFIG_POPCORN_HYPE
    VPCINETPRINTK("\tpophype: virtio: pci: net: irq: %s(): irq %d "
			"(24:virtio0-config 25:virtio0-input.0 26:virtio0-output.0)\n",
			__func__, vp_dev->msix_entries[v].vector);
#endif
	err = request_irq(vp_dev->msix_entries[v].vector,
			  vp_config_changed, 0, vp_dev->msix_names[v],
			  vp_dev);
	if (err)
		goto error;
	++vp_dev->msix_used_vectors;

	v = vp_dev->config_vector(vp_dev, v);
	/* Verify we had enough resources to assign the vector */
	if (v == VIRTIO_MSI_NO_VECTOR) {
		err = -EBUSY;
		goto error;
	}

	if (!per_vq_vectors) {
		/* Shared vector for all VQs */
		v = vp_dev->msix_used_vectors;
		snprintf(vp_dev->msix_names[v], sizeof *vp_dev->msix_names,
			 "%s-virtqueues", name);
#ifdef CONFIG_POPCORN_HYPE
    VPCINETPRINTK("\tpophype: virtio: pci: net: irq: %s(): irq %d "
			"(24:virtio0-config 25:virtio0-input.0 26:virtio0-output.0)\n",
			__func__, vp_dev->msix_entries[v].vector);
#endif
		err = request_irq(vp_dev->msix_entries[v].vector,
				  vp_vring_interrupt, 0, vp_dev->msix_names[v],
				  vp_dev);
		if (err)
			goto error;
		++vp_dev->msix_used_vectors;
	}
	return 0;
error:
	vp_free_vectors(vdev);
	return err;
}

static int vp_request_intx(struct virtio_device *vdev)
{
	int err;
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);

#ifdef CONFIG_POPCORN_HYPE
    VPCINETPRINTK("\tpophype: virtio: pci: net: irq: %s(): irq %d"
			"(24:virtio0-config 25:virtio0-input.0 26:virtio0-output.0)\n",
			__func__, vp_dev->pci_dev->irq);
#endif
	err = request_irq(vp_dev->pci_dev->irq, vp_interrupt,
			  IRQF_SHARED, dev_name(&vdev->dev), vp_dev);
	if (!err)
		vp_dev->intx_enabled = 1;
	return err;
}

static struct virtqueue *vp_setup_vq(struct virtio_device *vdev, unsigned index,
				     void (*callback)(struct virtqueue *vq),
				     const char *name,
				     u16 msix_vec)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct virtio_pci_vq_info *info = kmalloc(sizeof *info, GFP_KERNEL);
	struct virtqueue *vq;
	unsigned long flags;

	/* fill out our structure that represents an active queue */
	if (!info)
		return ERR_PTR(-ENOMEM);

#ifdef CONFIG_POPCORN_HYPE
    POP_PK("pophype: %s %s(): [[[vhost]]] vdev %p vp_dev %p "
			"callback %p name \"%s\" -> vp_dev->setup_vq "
			"(./drivers/virtio/virtio_pci_legacy.c) "
			"[register address to back end, vhost/lkvm] "
			"msix_vec 0x%x vp_dev->pci_dev->irq %d\n",
			__FILE__, __func__, vdev, vp_dev,
			callback, name, msix_vec, vp_dev->pci_dev->irq);
#endif

	vq = vp_dev->setup_vq(vp_dev, info, index, callback, name, msix_vec);
	if (IS_ERR(vq))
		goto out_info;

#ifdef CONFIG_POPCORN_HYPE
    POP_PK("pophype: %s %s(): [[[vhost]]] Jack "
			"vq(callback %p) %p pa 0x%llx name \"%s\"\n",
			__FILE__, __func__, callback, vq, virt_to_phys(vq), name);
#endif

	info->vq = vq;
	if (callback) {
		spin_lock_irqsave(&vp_dev->lock, flags);
		list_add(&info->node, &vp_dev->virtqueues);
		spin_unlock_irqrestore(&vp_dev->lock, flags);
	} else {
		INIT_LIST_HEAD(&info->node);
	}

	vp_dev->vqs[index] = info;
	return vq;

out_info:
	kfree(info);
	return vq;
}

static void vp_del_vq(struct virtqueue *vq)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vq->vdev);
	struct virtio_pci_vq_info *info = vp_dev->vqs[vq->index];
	unsigned long flags;

	spin_lock_irqsave(&vp_dev->lock, flags);
	list_del(&info->node);
	spin_unlock_irqrestore(&vp_dev->lock, flags);

	vp_dev->del_vq(info);
	kfree(info);
}

/* the config->del_vqs() implementation */
void vp_del_vqs(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct virtqueue *vq, *n;
	struct virtio_pci_vq_info *info;

	list_for_each_entry_safe(vq, n, &vdev->vqs, list) {
		info = vp_dev->vqs[vq->index];
		if (vp_dev->per_vq_vectors &&
			info->msix_vector != VIRTIO_MSI_NO_VECTOR)
			free_irq(vp_dev->msix_entries[info->msix_vector].vector,
				 vq);
		vp_del_vq(vq);
	}
	vp_dev->per_vq_vectors = false;

	vp_free_vectors(vdev);
	kfree(vp_dev->vqs);
	vp_dev->vqs = NULL;
}

static int vp_try_to_find_vqs(struct virtio_device *vdev, unsigned nvqs,
			      struct virtqueue *vqs[],
			      vq_callback_t *callbacks[],
			      const char *names[],
			      bool use_msix,
			      bool per_vq_vectors)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	u16 msix_vec;
	int i, err, nvectors, allocated_vectors;

#ifdef CONFIG_POPCORN_HYPE
    POP_PK("(guest) pophype: virtio-net-driver: net: pci: "
			"%s %s(): vdev %p vp_dev %p "
			"vp_dev->pci_dev->irq %u\n",
			__FILE__, __func__, vdev, vp_dev, vp_dev->pci_dev->irq);
    if (vp_dev) {
		if (vp_dev->pci_dev) {
			POP_PK("pophype: %s %s(): vp_dev->pci_dev->irq %u\n",
					__FILE__, __func__, vp_dev->pci_dev->irq);
		}
	}
#endif
	vp_dev->vqs = kmalloc(nvqs * sizeof *vp_dev->vqs, GFP_KERNEL);
	if (!vp_dev->vqs)
		return -ENOMEM;

	if (!use_msix) {
		/* Old style: one normal interrupt for change and all vqs. */
#ifdef CONFIG_POPCORN_HYPE
		POP_PK("\t\t(guest) pophype: virtio-net-driver: net: pci: "
			"%s %s(): irq %u 1 irq for all vqs and change int\n",
					__FILE__, __func__, vp_dev->pci_dev->irq);
#endif
		err = vp_request_intx(vdev);
		if (err)
			goto error_find;
	} else {
		if (per_vq_vectors) {
#ifdef CONFIG_POPCORN_HYPE
			POP_PK("\t\t(guest) pophype: virtio-net-driver: net: pci: "
					"%s %s(): irq %u 1 irq for each vqs, "
					"1 for change int\n",
					__FILE__, __func__, vp_dev->pci_dev->irq);
#endif
			/* Best option: one for change interrupt, one per vq. */
			nvectors = 1;
			for (i = 0; i < nvqs; ++i)
				if (callbacks[i])
					++nvectors;
		} else {
			/* Second best: one for change, shared for all vqs. */
#ifdef CONFIG_POPCORN_HYPE
			POP_PK("\t\t(guest) pophype: virtio-net-driver: net: pci: "
					"%s %s(): irq %u 1 irq for all vqs, "
					"1 for change int\n",
					__FILE__, __func__, vp_dev->pci_dev->irq);
#endif
			nvectors = 2;
		}

		err = vp_request_msix_vectors(vdev, nvectors, per_vq_vectors);
		if (err)
			goto error_find;
	}

	vp_dev->per_vq_vectors = per_vq_vectors;
	allocated_vectors = vp_dev->msix_used_vectors;
	for (i = 0; i < nvqs; ++i) {
#ifdef CONFIG_POPCORN_HYPE
		int irq;
#endif
		if (!names[i]) {
			vqs[i] = NULL;
			continue;
		} else if (!callbacks[i] || !vp_dev->msix_enabled)
			msix_vec = VIRTIO_MSI_NO_VECTOR;
		else if (vp_dev->per_vq_vectors)
			msix_vec = allocated_vectors++;
		else
			msix_vec = VP_MSIX_VQ_VECTOR;

#ifdef CONFIG_POPCORN_HYPE
		POP_PK("\t\t(guest) pophype: virtio-net-driver: net: pci: "
				"%s %s(): vp_setup_vq()\n", __FILE__, __func__);
#endif
		vqs[i] = vp_setup_vq(vdev, i, callbacks[i], names[i], msix_vec);
		if (IS_ERR(vqs[i])) {
			err = PTR_ERR(vqs[i]);
			goto error_find;
		}

		if (!vp_dev->per_vq_vectors || msix_vec == VIRTIO_MSI_NO_VECTOR)
			continue;

		/* allocate per-vq irq if available and necessary */
		snprintf(vp_dev->msix_names[msix_vec],
			 sizeof *vp_dev->msix_names,
			 "%s-%s",
			 dev_name(&vp_dev->vdev.dev), names[i]);
#ifdef CONFIG_POPCORN_HYPE
		irq = vp_dev->msix_entries[msix_vec].vector;
		/* pophype: TODO if name matches */
		VIRTIOBLKPK("%s(): msix=%d, irq=%d name \"%s-%s\" #%d/%d\n",
				__func__, msix_vec, vp_dev->msix_entries[msix_vec].vector,
				dev_name(&vp_dev->vdev.dev), names[i], i, nvqs);

		if (irq_can_set_affinity(irq)) {
			VPCINETPRINTK("\t\tpophype: virtio: pci: net: irq: %s(): "
					"irq %d CAN set irq\n",
					__func__, vp_dev->msix_entries[msix_vec].vector);
		} else {
			VPCINETPRINTK("\t\tpophype: virtio: pci: net: irq: %s(): "
					"irq %d CANNOT set irq\n",
					__func__, vp_dev->msix_entries[msix_vec].vector);
		}

		/* pophype - hack 25 26 pci in and out for NIC */
		if (irq == GUEST_X86_NET) { /* 26 pci-in, 26 pci-out: cannot */
			struct irq_desc *desc = irq_to_desc(irq);
			if (desc) {
				if (desc->irq_data.chip) {
					if (desc->irq_data.chip->irq_set_affinity) {
						AFFPRINTK("%s(): over writing affinity\n", __func__);
						AFFPRINTK("%s() check: bf "
							"smp_irq_set_affinity_callback() %p "
							"name \"%s\" cpu %*pbl %*pb\n", __func__,
							desc->irq_data.chip->irq_set_affinity,
							desc->irq_data.chip->name,
							cpumask_pr_args(desc->irq_common_data.affinity),
							cpumask_pr_args(desc->irq_common_data.affinity));

						/* hardcoded */
						//cpumask_var_t tmpmask;
						//cpumask_set_cpu(0, tmpmask); // pin the irq on cpu0. cpumask =
						//int ret = ;
						//irq_set_affinity(irq, cpumask_of(0));
						irq_set_affinity(irq, cpumask_of(1));
						irq_set_affinity(irq, cpumask_of(1));
						/* request_irq will over write it */

						AFFPRINTK("%s() check: af "
							"smp_irq_set_affinity_callback() %p "
							"name \"%s\" cpu %*pbl %*pb\n", __func__,
							desc->irq_data.chip->irq_set_affinity,
							desc->irq_data.chip->name,
							cpumask_pr_args(desc->irq_common_data.affinity),
							cpumask_pr_args(desc->irq_common_data.affinity));
					} else {
						AFFPRINTK("%s() check: "
							"!smp_irq_set_affinity_callback()\n", __func__);
					}
				} else {
					  AFFPRINTK("%s() check: !desc->irq_data.chip case\n",
																	__func__);
				}
			} else {
			  AFFPRINTK("%s() check: !desc case\n", __func__);
			}
		}
#endif
		err = request_irq(vp_dev->msix_entries[msix_vec].vector,
				  vring_interrupt, 0,
				  vp_dev->msix_names[msix_vec],
				  vqs[i]);
		if (err) {
			vp_del_vq(vqs[i]);
			goto error_find;
		}
	}
	return 0;

error_find:
	vp_del_vqs(vdev);
	return err;
}

/* the config->find_vqs() implementation */
int vp_find_vqs(struct virtio_device *vdev, unsigned nvqs,
		struct virtqueue *vqs[],
		vq_callback_t *callbacks[],
		const char *names[])
{
	int err;

#ifdef CONFIG_POPCORN_HYPE
	POP_PK("\t (guest) pophype: virtio-net-driver: net: pci: %s():\n",
															__func__);
#endif

	/* Try MSI-X with one vector per queue. */
	err = vp_try_to_find_vqs(vdev, nvqs, vqs, callbacks, names, true, true);
	if (!err)
		return 0;
	/* Fallback: MSI-X with one vector for config, one shared for queues. */
	err = vp_try_to_find_vqs(vdev, nvqs, vqs, callbacks, names,
				 true, false);
	if (!err)
		return 0;
	/* Finally fall back to regular interrupts. */
	return vp_try_to_find_vqs(vdev, nvqs, vqs, callbacks, names,
				  false, false);
}

const char *vp_bus_name(struct virtio_device *vdev)
{
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);

	return pci_name(vp_dev->pci_dev);
}

/* Setup the affinity for a virtqueue:
 * - force the affinity for per vq vector
 * - OR over all affinities for shared MSI
 * - ignore the affinity request if we're using INTX
 */
int vp_set_vq_affinity(struct virtqueue *vq, int cpu)
{
	struct virtio_device *vdev = vq->vdev;
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);
	struct virtio_pci_vq_info *info = vp_dev->vqs[vq->index];
	struct cpumask *mask;
	unsigned int irq;

	if (!vq->callback)
		return -EINVAL;

	if (vp_dev->msix_enabled) {
		mask = vp_dev->msix_affinity_masks[info->msix_vector];
		irq = vp_dev->msix_entries[info->msix_vector].vector;
		if (cpu == -1)
			irq_set_affinity_hint(irq, NULL);
		else {
			cpumask_clear(mask);
			cpumask_set_cpu(cpu, mask);
			irq_set_affinity_hint(irq, mask);
		}
	}
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int virtio_pci_freeze(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_pci_device *vp_dev = pci_get_drvdata(pci_dev);
	int ret;

	ret = virtio_device_freeze(&vp_dev->vdev);

	if (!ret)
		pci_disable_device(pci_dev);
	return ret;
}

static int virtio_pci_restore(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_pci_device *vp_dev = pci_get_drvdata(pci_dev);
	int ret;

	ret = pci_enable_device(pci_dev);
	if (ret)
		return ret;

	pci_set_master(pci_dev);
	return virtio_device_restore(&vp_dev->vdev);
}

static const struct dev_pm_ops virtio_pci_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(virtio_pci_freeze, virtio_pci_restore)
};
#endif


/* Qumranet donated their vendor ID for devices 0x1000 thru 0x10FF. */
static const struct pci_device_id virtio_pci_id_table[] = {
	{ PCI_DEVICE(0x1af4, PCI_ANY_ID) },
	{ 0 }
};

MODULE_DEVICE_TABLE(pci, virtio_pci_id_table);

static void virtio_pci_release_dev(struct device *_d)
{
	struct virtio_device *vdev = dev_to_virtio(_d);
	struct virtio_pci_device *vp_dev = to_vp_device(vdev);

	/* As struct device is a kobject, it's not safe to
	 * free the memory (including the reference counter itself)
	 * until it's release callback. */
	kfree(vp_dev);
}

static int virtio_pci_probe(struct pci_dev *pci_dev,
			    const struct pci_device_id *id)
{
	struct virtio_pci_device *vp_dev;
	int rc;

#ifdef CONFIG_POPCORN_HYPE
    POP_PK("%s(): [[[vhost]]] pci_dev %p "
			"pci_device_id vendor %u device %u"
			"subvendor %u subdevice %u (1:net 3:console)\n",
					__func__, pci_dev, id->vendor, id->device,
								id->subvendor, id->subdevice);
#endif

	/* allocate our structure and fill it out */
	vp_dev = kzalloc(sizeof(struct virtio_pci_device), GFP_KERNEL);
	if (!vp_dev)
		return -ENOMEM;

	pci_set_drvdata(pci_dev, vp_dev);
	vp_dev->vdev.dev.parent = &pci_dev->dev;
	vp_dev->vdev.dev.release = virtio_pci_release_dev;
	vp_dev->pci_dev = pci_dev;
	INIT_LIST_HEAD(&vp_dev->virtqueues);
	spin_lock_init(&vp_dev->lock);

	/* enable the device */
	rc = pci_enable_device(pci_dev);
	if (rc)
		goto err_enable_device;

	if (force_legacy) {
		rc = virtio_pci_legacy_probe(vp_dev);
		/* Also try modern mode if we can't map BAR0 (no IO space). */
		if (rc == -ENODEV || rc == -ENOMEM)
			rc = virtio_pci_modern_probe(vp_dev);
		if (rc)
			goto err_probe;
	} else {
		rc = virtio_pci_modern_probe(vp_dev);
		if (rc == -ENODEV)
			rc = virtio_pci_legacy_probe(vp_dev);
		if (rc)
			goto err_probe;
	}

	pci_set_master(pci_dev);

	rc = register_virtio_device(&vp_dev->vdev);
	if (rc)
		goto err_register;

	return 0;

err_register:
	if (vp_dev->ioaddr)
	     virtio_pci_legacy_remove(vp_dev);
	else
	     virtio_pci_modern_remove(vp_dev);
err_probe:
	pci_disable_device(pci_dev);
err_enable_device:
	kfree(vp_dev);
	return rc;
}

static void virtio_pci_remove(struct pci_dev *pci_dev)
{
	struct virtio_pci_device *vp_dev = pci_get_drvdata(pci_dev);
	struct device *dev = get_device(&vp_dev->vdev.dev);

	unregister_virtio_device(&vp_dev->vdev);

	if (vp_dev->ioaddr)
		virtio_pci_legacy_remove(vp_dev);
	else
		virtio_pci_modern_remove(vp_dev);

	pci_disable_device(pci_dev);
	put_device(dev);
}

static struct pci_driver virtio_pci_driver = {
	.name		= "virtio-pci",
	.id_table	= virtio_pci_id_table,
	.probe		= virtio_pci_probe,
	.remove		= virtio_pci_remove,
#ifdef CONFIG_PM_SLEEP
	.driver.pm	= &virtio_pci_pm_ops,
#endif
};

module_pci_driver(virtio_pci_driver);

MODULE_AUTHOR("Anthony Liguori <aliguori@us.ibm.com>");
MODULE_DESCRIPTION("virtio-pci");
MODULE_LICENSE("GPL");
MODULE_VERSION("1");
