"""
Module pour gérer la diminution du volume des suppléments dans un système de dosage automatique.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from copy import deepcopy
import json
import random

from supplements_list import SUPPLEMENTS


@dataclass
class Supplement:
    """Représente un supplément avec ses propriétés."""

    uid: str
    name: str
    short_name: str
    # Ajoutez d'autres champs selon votre structure de données


@dataclass
class DoseSlot:
    """Représente un créneau de dosage dans la file d'attente."""

    head: str
    time: int  # Minutes depuis minuit (0-1440)
    volume: float
    dose_type: str = "Auto"


@dataclass
class Head:
    """Représente une tête de distribution avec son état."""

    supplement: Dict[str, Any]
    daily_dose: float
    daily_doses: int
    initial_container_volume: float
    container_volume: float = 0.0
    doses_today: int = 0

    def reset_daily_doses(self) -> None:
        """Réinitialise le compteur de doses quotidiennes."""
        self.doses_today = 0

    def dispense_dose(self) -> bool:
        """
        Distribue une dose si possible.

        Returns:
            True si la dose a été distribuée, False sinon.
        """
        if self.container_volume <= 0 or self.doses_today >= self.daily_doses:
            return False

        dose_volume = self.daily_dose / self.daily_doses
        self.container_volume -= dose_volume
        if self.container_volume < 0:
            self.container_volume = 0
        self.doses_today += 1
        return True

    def refill(self, amount: float = 10.0) -> None:
        """Remplit le conteneur d'une quantité donnée."""
        self.container_volume = min(self.container_volume + amount, 100.0)

    def get_remaining_days(self) -> int:
        """Calcule le nombre de jours restants avec le volume actuel."""
        if self.daily_dose <= 0:
            return 0
        return int(self.container_volume // self.daily_dose)

    def is_empty(self) -> bool:
        """Vérifie si le conteneur est vide."""
        return self.container_volume <= 0


@dataclass
class DecreaseVolumeContext:
    """Contexte pour gérer l'état du système de dosage."""

    heads: Dict[str, Head] = field(default_factory=dict)
    refill: bool = False
    dosing_queue: List[DoseSlot] = field(default_factory=list)
    total_daily_doses: int = 0
    remaining_doses_in_queue: int = 0

    def initialize_head(self, head_id: str, head_config: Any) -> None:
        """
        Initialise une tête de distribution.

        Args:
            head_id: Identifiant de la tête
            head_config: Configuration de la tête
        """
        supplement = get_supplement(head_config.supplement)
        if supplement is None:
            raise ValueError(f"Supplément non trouvé: {head_config.supplement}")

        head = Head(
            supplement=supplement,
            daily_dose=head_config.daily_dose,
            daily_doses=head_config.daily_doses,
            initial_container_volume=head_config.initial_container_volume,
            container_volume=head_config.initial_container_volume,
        )
        self.heads[head_id] = head
        self.total_daily_doses += head.daily_doses

        # Ajouter les créneaux de dosage
        self._add_dosing_slots_for_head(head)

    def _add_dosing_slots_for_head(self, head: Head) -> None:
        """Ajoute les créneaux de dosage pour une tête."""
        dose_volume = head.daily_dose / head.daily_doses
        for _ in range(head.daily_doses):
            slot = DoseSlot(
                head=head.supplement["short_name"],
                time=random.randint(0, 1440),
                volume=dose_volume,
            )
            self.dosing_queue.append(slot)

    def sort_dosing_queue(self) -> None:
        """Trie la file d'attente de dosage par horaire."""
        self.dosing_queue.sort(key=lambda slot: slot.time)

    def reset_new_day(self) -> None:
        """Réinitialise les compteurs pour un nouveau jour."""
        for head in self.heads.values():
            head.reset_daily_doses()
        self.remaining_doses_in_queue = self.total_daily_doses

    def count_ready_for_new_day(self) -> int:
        """Compte le nombre de têtes prêtes pour un nouveau jour."""
        count = 0
        for head in self.heads.values():
            if head.is_empty() or head.doses_today >= head.daily_doses:
                count += 1
        return count

    def count_empty_containers(self) -> int:
        """Compte le nombre de conteneurs vides."""
        return sum(1 for head in self.heads.values() if head.is_empty())

    def should_refill(self) -> bool:
        """Vérifie si un remplissage est nécessaire."""
        return self.count_empty_containers() >= len(self.heads)

    def refill_all_containers(self, amount: float = 10.0) -> None:
        """Remplit tous les conteneurs."""
        for head in self.heads.values():
            head.refill(amount)
        # Vérifier si le remplissage est terminé
        if any(head.container_volume + amount > 100 for head in self.heads.values()):
            self.refill = False


def get_supplement(uid: str) -> Optional[Dict[str, Any]]:
    """
    Récupère un supplément par son UID.

    Args:
        uid: Identifiant unique du supplément

    Returns:
        Dictionnaire contenant les informations du supplément ou None si non trouvé.
    """
    for supplement in SUPPLEMENTS:
        if supplement["uid"] == uid:
            return json.loads(json.dumps(supplement))
    return None


def initialize_context(ctx: Any, params: Any) -> DecreaseVolumeContext:
    """
    Initialise le contexte de dosage.

    Args:
        ctx: Contexte global
        params: Paramètres de configuration

    Returns:
        Contexte de dosage initialisé.
    """
    if hasattr(ctx, "decrease_volume"):
        return ctx.decrease_volume

    context = DecreaseVolumeContext()

    # Initialiser les têtes
    for attr_name in dir(params):
        if attr_name.startswith("head_"):
            head_id = attr_name.replace("head_", "")
            head_config = getattr(params, attr_name)
            context.initialize_head(head_id, head_config)

    context.sort_dosing_queue()
    context.remaining_doses_in_queue = context.total_daily_doses

    ctx.decrease_volume = context
    return context


def process_dashboard(
    context: DecreaseVolumeContext, result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Traite la requête pour le tableau de bord.

    Args:
        context: Contexte de dosage
        result: Données de résultat à modifier

    Returns:
        Données du tableau de bord mises à jour.
    """
    new_day_ready_count = 0
    empty_container_count = 0

    # Distribuer les doses si pas en mode remplissage
    if not context.refill:
        for head_id, head in context.heads.items():
            if head.container_volume > 0:
                if head.doses_today >= head.daily_doses:
                    new_day_ready_count += 1
                else:
                    if head.dispense_dose():
                        context.remaining_doses_in_queue -= 1
                result["heads"][head_id]["state"] = "on"
            else:
                result["heads"][head_id]["state"] = "off"
                new_day_ready_count += 1
                empty_container_count += 1

    # Mettre à jour les informations de chaque tête
    for head_id, head in context.heads.items():
        result["heads"][head_id].update(
            {
                "state": "on",
                "supplement": head.supplement["name"],
                "daily_dose": head.daily_dose,
                "daily_doses": head.daily_doses,
                "doses_today": head.doses_today,
                "auto_dosed_today": (head.daily_dose / head.daily_doses)
                * head.doses_today,
                "remaining_days": head.get_remaining_days(),
            }
        )

    # Vérifier si c'est un nouveau jour
    if new_day_ready_count >= len(context.heads):
        context.reset_new_day()

    # Gérer le remplissage
    if context.refill:
        context.refill_all_containers()
    elif empty_container_count >= len(context.heads):
        context.refill = True
        context.refill_all_containers()

    return result


def process_head(
    context: DecreaseVolumeContext, head_id: str, result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Traite la requête pour une tête spécifique.

    Args:
        context: Contexte de dosage
        head_id: Identifiant de la tête
        result: Données de résultat à modifier

    Returns:
        Informations de la tête mises à jour.
    """
    if head_id not in context.heads:
        raise ValueError(f"Tête non trouvée: {head_id}")

    head = context.heads[head_id]

    result.update(
        {
            "slm": True,
            "container_volume": head.container_volume,
            "state": "on" if head.container_volume > 0 else "off",
            "schedule_enabled": head.container_volume > 0,
            "supplement": head.supplement,
        }
    )

    return result


def process_dosing_queue(context: DecreaseVolumeContext) -> List[Dict[str, Any]]:
    """
    Traite la requête pour la file d'attente de dosage.

    Args:
        context: Contexte de dosage

    Returns:
        Liste des créneaux de dosage restants.
    """
    queue = deepcopy(context.dosing_queue)

    # Retirer les doses déjà distribuées
    doses_dispensed = context.total_daily_doses - context.remaining_doses_in_queue
    for _ in range(doses_dispensed):
        if queue:
            queue.pop(0)

    # Filtrer les créneaux pour les conteneurs vides
    for head in context.heads.values():
        if head.is_empty():
            queue = [
                slot for slot in queue if slot.head != head.supplement["short_name"]
            ]

    # Convertir en dictionnaires pour la sortie
    return [
        {
            "head": slot.head,
            "time": slot.time,
            "volume": slot.volume,
            "dose_type": slot.dose_type,
        }
        for slot in queue
    ]


def decrease_volume(path: str, data: Dict[str, Any], params: Any, ctx: Any) -> Any:
    """
    Fonction principale pour gérer la diminution du volume des suppléments.

    Args:
        path: Chemin de la requête
        data: Données d'entrée
        params: Paramètres de configuration
        ctx: Contexte global

    Returns:
        Données mises à jour selon le chemin de la requête.
    """
    # Initialiser le contexte si nécessaire
    context = initialize_context(ctx, params)

    # Créer une copie des données de résultat
    result = json.loads(json.dumps(data))

    # Router selon le chemin
    if path == "/dashboard":
        return process_dashboard(context, result)

    elif path.startswith("/head/"):
        head_id = path.split("/")[2]
        return process_head(context, head_id, result)

    elif path == "/dosing-queue":
        return process_dosing_queue(context)

    return result
